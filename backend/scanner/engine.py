import asyncio
import socket
import time
import uuid
from datetime import datetime, timezone
from urllib.parse import urlparse
import httpx

from backend.models import (
    ScanRequest, ScanResult, ScanSummary, Severity, Finding
)
from backend.scanner.headers import analyze_headers
from backend.scanner.ssl_checker import check_ssl
from backend.scanner.tech_detector import detect_technologies
from backend.scanner.recon import check_recon_endpoints
from backend.scanner.passive_audit import audit_cors, audit_http_options, audit_html_security
from backend.scanner.metasploit_db import METASPLOIT_RULES, generate_metasploit_suggestions

# Cookie findings carry the cookie name in their id (e.g. "cookie-no-secure-shop_ref").
# These prefixes let the scorer collapse repeated findings of the same type into one
# penalty, so a site with many cookies is not penalised once per cookie.
_COOKIE_FINDING_PREFIXES = (
    "cookie-no-secure",
    "cookie-no-httponly",
    "cookie-missing-samesite",
    "cookie-insecure-samesite-none",
    "cookie-samesite-none",
)

def _finding_type(finding: Finding) -> str:
    """Return the finding type key used for score grouping (cookie name removed)."""
    for prefix in _COOKIE_FINDING_PREFIXES:
        if finding.id == prefix or finding.id.startswith(prefix + "-"):
            return prefix
    return finding.id

def calculate_security_score(findings: list[Finding]) -> tuple[int, str]:
    """
    Score rule: start at 100 and subtract ONE penalty per finding TYPE, not per
    finding instance. Findings that share the same type (for example "Cookie
    Without Secure Flag" across three different cookies) count once, using the
    worst severity present for that type. Weights: CRITICAL -25, HIGH -15,
    MEDIUM -8, LOW -3, INFO 0. The score is clamped to 0..100. The findings
    list itself is never modified.
    """
    weights = {
        Severity.CRITICAL: 25,
        Severity.HIGH: 15,
        Severity.MEDIUM: 8,
        Severity.LOW: 3,
        Severity.INFO: 0,
    }

    penalties: dict[str, int] = {}
    for f in findings:
        key = _finding_type(f)
        penalty = weights.get(f.severity, 0)
        if penalty > penalties.get(key, 0):
            penalties[key] = penalty

    score = max(0, min(100, 100 - sum(penalties.values())))

    if score >= 90:
        grade = "A"
    elif score >= 80:
        grade = "B"
    elif score >= 70:
        grade = "C"
    elif score >= 55:
        grade = "D"
    else:
        grade = "F"

    return score, grade

def apply_manual_checks(findings: list[Finding]) -> None:
    """
    R6-C5: attach a passive, read-only manual verification hint to every finding
    that no Metasploit rule covers (matching is done on finding ids only).
    Findings that already carry a specific hint keep it.
    """
    module_finding_ids = {
        finding_id
        for rule in METASPLOIT_RULES
        for finding_id in rule.get("finding_id_match", [])
    }
    for finding in findings:
        if not finding.manual_check and finding.id not in module_finding_ids:
            finding.manual_check = (
                "No Metasploit module is mapped to this check. Verify manually from the "
                "evidence above and the remediation guidance (read-only review; no active "
                "request is needed)."
            )

async def run_scan(request: ScanRequest) -> ScanResult:
    start_time = time.time()
    scan_id = str(uuid.uuid4())

    # Normalize URL
    target_url = request.url.strip()
    if not target_url.startswith(("http://", "https://")):
        target_url = "https://" + target_url

    parsed = urlparse(target_url)
    hostname = parsed.hostname or "localhost"
    is_https = (parsed.scheme == "https")

    # Resolve IP (off the event loop, same pattern as check_ssl)
    ip_address = None
    try:
        loop = asyncio.get_event_loop()
        ip_address = await loop.run_in_executor(None, socket.gethostbyname, hostname)
    except Exception:
        ip_address = "Unable to resolve"

    all_findings: list[Finding] = []
    headers_analyzed = {}
    ssl_info = None
    technologies = []
    recon_items = []
    
    headers_to_send = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AegisWeb-SecurityAudit/1.1 (Defensive Assessment Tool)",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
    }

    async with httpx.AsyncClient(headers=headers_to_send, verify=False, follow_redirects=True, timeout=request.timeout) as client:
        try:
            # 1. Primary Request
            response = await client.get(target_url)
            body_text = response.text
            response_headers = dict(response.headers)
            
            # Extract cookies safely (handling case-insensitive attributes in _rest)
            cookies_list = []
            for cookie in response.cookies.jar:
                # HttpOnly check
                is_httponly = cookie.has_nonstandard_attr("HttpOnly") or any(
                    k.lower() == "httponly" for k in getattr(cookie, "_rest", {}).keys()
                )
                
                # SameSite check (properly reading _rest dict case-insensitively)
                samesite_val = ""
                rest_dict = getattr(cookie, "_rest", {})
                if isinstance(rest_dict, dict):
                    for k, v in rest_dict.items():
                        if k.lower() == "samesite":
                            samesite_val = (v or "Lax").lower()
                            break

                cookies_list.append({
                    "name": cookie.name,
                    "value": cookie.value,
                    "domain": cookie.domain,
                    "path": cookie.path,
                    "secure": cookie.secure,
                    "httponly": is_httponly,
                    "samesite": samesite_val
                })

            # 2. Header & Cookie Analysis
            if request.scan_headers:
                header_findings, headers_analyzed = analyze_headers(response_headers, cookies_list, is_https)
                all_findings.extend(header_findings)

                # Passive audits: CORS, HTTP Methods, and HTML Content Security (Mixed content & SRI)
                cors_findings = await audit_cors(client, target_url)
                all_findings.extend(cors_findings)

                options_findings, allowed_methods = await audit_http_options(client, target_url)
                all_findings.extend(options_findings)
                if allowed_methods:
                    headers_analyzed["allowed_http_methods"] = ", ".join(allowed_methods)

                html_sec_findings = audit_html_security(body_text, is_https, base_url=target_url)
                all_findings.extend(html_sec_findings)

            # 3. Technology fingerprinting
            technologies = detect_technologies(response_headers, body_text, cookies_list)

            # 4. Safe Recon discovery
            if request.scan_recon:
                recon_items, recon_findings = await check_recon_endpoints(client, str(response.url))
                all_findings.extend(recon_findings)

        except Exception as e:
            # If primary request fails, record error
            duration = round(time.time() - start_time, 2)
            return ScanResult(
                scan_id=scan_id,
                target_url=target_url,
                hostname=hostname,
                ip_address=ip_address,
                scan_time=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
                duration_seconds=duration,
                status="failed",
                error=f"Connection error: {str(e)}",
                summary=ScanSummary(score=0, grade="F"),
                findings=[Finding(
                    id="connection-failure",
                    title="Target Host Unreachable",
                    severity=Severity.HIGH,
                    category="Connectivity",
                    description=f"Could not establish connection to {target_url}: {str(e)}",
                    impact="Scanner cannot audit unreachable endpoints.",
                    remediation="Check target hostname, DNS resolution, firewall status, and port availability.",
                    manual_check="Re-run the scan after confirming DNS resolution and that the host is reachable over HTTP/HTTPS (for example with a browser or curl -I); no other action is needed."
                )]
            )

    # 5. SSL / TLS Certificate Analysis (Always runs if scan_ssl is enabled, regardless of http/https)
    if request.scan_ssl:
        loop = asyncio.get_event_loop()
        ssl_info, ssl_findings = await loop.run_in_executor(None, check_ssl, target_url, request.timeout)
        all_findings.extend(ssl_findings)

    # 6. Generate Metasploit Suggestions
    msf_suggestions = generate_metasploit_suggestions(target_url, technologies, all_findings)

    # C5: every finding without a module gets a passive "how to verify" hint.
    apply_manual_checks(all_findings)

    # 7. Summary metrics & scoring
    score, grade = calculate_security_score(all_findings)
    crit_count = sum(1 for f in all_findings if f.severity == Severity.CRITICAL)
    high_count = sum(1 for f in all_findings if f.severity == Severity.HIGH)
    med_count = sum(1 for f in all_findings if f.severity == Severity.MEDIUM)
    low_count = sum(1 for f in all_findings if f.severity == Severity.LOW)
    info_count = sum(1 for f in all_findings if f.severity == Severity.INFO)

    summary = ScanSummary(
        score=score,
        grade=grade,
        total_findings=len(all_findings),
        critical=crit_count,
        high=high_count,
        medium=med_count,
        low=low_count,
        info=info_count
    )

    duration = round(time.time() - start_time, 2)

    return ScanResult(
        scan_id=scan_id,
        target_url=target_url,
        hostname=hostname,
        ip_address=ip_address,
        scan_time=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        duration_seconds=duration,
        status="completed",
        summary=summary,
        findings=all_findings,
        headers_analyzed=headers_analyzed,
        ssl_info=ssl_info,
        technologies=technologies,
        metasploit_suggestions=msf_suggestions,
        recon_items=recon_items
    )
