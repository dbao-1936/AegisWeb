import re
import httpx
from typing import List, Dict, Any, Tuple, Optional
from urllib.parse import urlparse
from backend.models import Finding, Severity

async def audit_cors(client: httpx.AsyncClient, base_url: str) -> List[Finding]:
    findings: List[Finding] = []
    test_origin = "https://untrusted-security-audit.example.com"

    try:
        resp = await client.get(base_url, headers={"Origin": test_origin}, timeout=5.0)
        acao = resp.headers.get("access-control-allow-origin", "").strip()
        acac = resp.headers.get("access-control-allow-credentials", "").strip().lower()

        # Vulnerable pattern 1: Arbitrary origin reflected with credentials
        if acao == test_origin and acac == "true":
            findings.append(Finding(
                id="cors-arbitrary-origin-credentials",
                title="Critical CORS Misconfiguration: Arbitrary Origin Trusted With Credentials",
                severity=Severity.HIGH,
                category="CORS Policy",
                description="The server reflects any arbitrary untrusted Origin header in 'Access-Control-Allow-Origin' while enabling 'Access-Control-Allow-Credentials: true'.",
                evidence=f"Request Origin: {test_origin} -> Response ACAO: {acao}, ACAC: {acac}",
                impact="Malicious external websites can issue authenticated JavaScript requests to read sensitive user session data and bypass the Same-Origin Policy.",
                remediation="Do not blindly reflect the Origin header. Maintain a strict whitelist of trusted partner domains, or avoid setting Access-Control-Allow-Credentials to true when using dynamic origins.",
                references=["https://portswigger.net/web-security/cors"]
            ))
        elif acao == "*" and acac == "true":
            findings.append(Finding(
                id="cors-wildcard-credentials",
                title="Insecure CORS: Wildcard Origin With Credentials",
                severity=Severity.HIGH,
                category="CORS Policy",
                description="Server specifies 'Access-Control-Allow-Origin: *' combined with 'Access-Control-Allow-Credentials: true'.",
                evidence="ACAO: * | ACAC: true",
                impact="Modern browsers block this combination, but misconfiguration indicates flawed access control logic.",
                remediation="Specify an explicit trusted origin instead of '*' when credentials are required.",
                references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS"]
            ))
        elif acao == "*":
            findings.append(Finding(
                id="cors-wildcard",
                title="Permissive CORS Policy (Wildcard Origin)",
                severity=Severity.INFO,
                category="CORS Policy",
                description="The server allows any origin to read public API responses via 'Access-Control-Allow-Origin: *'.",
                evidence="Access-Control-Allow-Origin: *",
                impact="Acceptable for purely public data, but exposes internal API endpoints if applied globally.",
                remediation="Ensure wildcard CORS is only enabled on endpoints intended to be 100% public.",
                references=["https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny"]
            ))

    except Exception:
        pass

    return findings

async def audit_http_options(client: httpx.AsyncClient, base_url: str) -> Tuple[List[Finding], List[str]]:
    findings: List[Finding] = []
    allowed_methods: List[str] = []

    try:
        resp = await client.options(base_url, timeout=5.0)
        allow_header = resp.headers.get("allow") or resp.headers.get("public") or ""
        
        if allow_header:
            allowed_methods = [m.strip().upper() for m in allow_header.split(",") if m.strip()]

            # 1. TRACE / TRACK method
            if "TRACE" in allowed_methods or "TRACK" in allowed_methods:
                findings.append(Finding(
                    id="http-trace-enabled",
                    title="Insecure HTTP TRACE/TRACK Method Enabled",
                    severity=Severity.MEDIUM,
                    category="HTTP Methods",
                    description="The web server has the HTTP TRACE (or TRACK) method enabled.",
                    evidence=f"Allow header: {allow_header}",
                    impact="Enables Cross-Site Tracing (XST) attacks, which can bypass HttpOnly cookie protection by reflecting the entire client request including headers.",
                    remediation="Disable HTTP TRACE/TRACK in the web server configuration (e.g., 'TraceEnable off' in Apache).",
                    references=["https://owasp.org/www-community/attacks/Cross_Site_Tracing"]
                ))

            # 2. Dangerous methods: PUT, DELETE (unless intended API)
            risky_methods = [m for m in allowed_methods if m in ["PUT", "DELETE"]]
            if risky_methods:
                findings.append(Finding(
                    id="http-risky-methods",
                    title=f"Potentially Dangerous HTTP Methods Enabled ({', '.join(risky_methods)})",
                    severity=Severity.LOW,
                    category="HTTP Methods",
                    description=f"Server advertises support for sensitive HTTP methods: {', '.join(risky_methods)}.",
                    evidence=f"Allow: {allow_header}",
                    impact="If authentication is misconfigured, attackers might be able to create, modify, or delete files on the server.",
                    remediation="Verify whether PUT/DELETE are required. If not, restrict permitted methods to GET, POST, and HEAD.",
                    references=["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/06-Test_HTTP_Methods"]
                ))
    except Exception:
        pass

    return findings, allowed_methods

def audit_html_security(html_text: str, is_https: bool, base_url: str = "") -> List[Finding]:
    findings: List[Finding] = []
    if not html_text:
        return findings

    # Determine base host for dynamic third-party hostname comparison
    target_host = ""
    if base_url:
        try:
            target_host = (urlparse(base_url).hostname or "").lower()
        except Exception:
            target_host = ""

    # 1. Mixed Content check (Active vs Passive) - Only relevant if target is HTTPS
    if is_https:
        active_matches: List[str] = []
        passive_matches: List[str] = []

        # A. Check <script src="http://...">
        script_src_pattern = re.compile(r'<script\b[^>]*\bsrc\s*=\s*["\'](http://[^"\']+)["\']', re.IGNORECASE)
        for m in script_src_pattern.finditer(html_text):
            active_matches.append(m.group(1))

        # B. Check <iframe src="http://...">
        iframe_src_pattern = re.compile(r'<iframe\b[^>]*\bsrc\s*=\s*["\'](http://[^"\']+)["\']', re.IGNORECASE)
        for m in iframe_src_pattern.finditer(html_text):
            active_matches.append(m.group(1))

        # C. Check <link ...> order-independently (href before rel or rel before href)
        link_tag_pattern = re.compile(r'<link\b([^>]+)>', re.IGNORECASE)
        for m in link_tag_pattern.finditer(html_text):
            attrs = m.group(1)
            # Match rel with stylesheet or preload
            if re.search(r'\brel\s*=\s*["\'][^"\']*\b(?:stylesheet|import)\b[^"\']*["\']', attrs, re.IGNORECASE):
                href_match = re.search(r'\bhref\s*=\s*["\'](http://[^"\']+)["\']', attrs, re.IGNORECASE)
                if href_match:
                    active_matches.append(href_match.group(1))

        # D. Check passive media: <img>, <audio>, <video>, <source>
        passive_pattern = re.compile(r'<(?:img|audio|video|source)\b[^>]*\bsrc\s*=\s*["\'](http://[^"\']+)["\']', re.IGNORECASE)
        for m in passive_pattern.finditer(html_text):
            passive_matches.append(m.group(1))

        # Active mixed content finding
        if active_matches:
            findings.append(Finding(
                id="mixed-content-active",
                title="Active Mixed Content Detected Over HTTPS",
                severity=Severity.HIGH,
                category="Content Security",
                description=f"HTTPS page attempts to load active executable resources (scripts/stylesheets/iframes) over unencrypted HTTP: {active_matches[0]}",
                evidence=f"Found {len(active_matches)} active resource(s) using http:// (e.g. {active_matches[0]})",
                impact="Network eavesdroppers can tamper with the unencrypted script to execute malicious code within the secure HTTPS origin (Man-in-the-Middle).",
                remediation="Upgrade all resource URLs to 'https://' or use protocol-relative URLs. Add 'Content-Security-Policy: upgrade-insecure-requests'.",
                references=["https://developer.mozilla.org/en-US/docs/Web/Security/Mixed_content"]
            ))

        # Passive mixed content finding: using IF (not elif) so both can be reported simultaneously!
        if passive_matches:
            findings.append(Finding(
                id="mixed-content-passive",
                title="Passive Mixed Content Detected Over HTTPS",
                severity=Severity.LOW,
                category="Content Security",
                description=f"HTTPS page attempts to load passive resources (images/media) over unencrypted HTTP: {passive_matches[0]}",
                evidence=f"Found {len(passive_matches)} passive image/media resource(s) using http:// (e.g. {passive_matches[0]})",
                impact="Adversaries can alter images or track user behavior via unencrypted media downloads.",
                remediation="Change all image and media references to 'https://'.",
                references=["https://developer.mozilla.org/en-US/docs/Web/Security/Mixed_content"]
            ))

    # 2. Subresource Integrity (SRI) Check - Expanded dynamically by Hostname
    # Checks any external script loaded from a third-party host that lacks the integrity attribute
    script_tag_pattern = re.compile(r'<script\b([^>]*)>', re.IGNORECASE)
    missing_sri_scripts: List[Tuple[str, str]] = [] # (src_url, host)

    for match in script_tag_pattern.finditer(html_text):
        tag_attrs = match.group(1)
        src_match = re.search(r'\bsrc\s*=\s*["\']([^"\']+)["\']', tag_attrs, re.IGNORECASE)
        if not src_match:
            continue

        src_url = src_match.group(1).strip()
        
        # Only evaluate absolute URLs pointing to external domains
        if src_url.startswith(("http://", "https://", "//")):
            normalized_url = "https:" + src_url if src_url.startswith("//") else src_url
            try:
                parsed_src = urlparse(normalized_url)
                script_host = (parsed_src.hostname or "").lower()
            except Exception:
                continue

            if not script_host:
                continue

            # Check if this script host is third-party (cross-origin relative to target_host)
            is_third_party = False
            if target_host:
                # Considered third party if host is different and not a subdomain of target
                if script_host != target_host and not script_host.endswith("." + target_host):
                    is_third_party = True
            else:
                # If target_host not known, match common CDN or external host pattern
                common_cdns = ("cdn", "cdnjs", "unpkg", "stackpath", "googleapis", "jsdelivr", "cloudflare", "facebook", "google")
                if any(c in script_host for c in common_cdns):
                    is_third_party = True

            if is_third_party:
                has_integrity = bool(re.search(r'\bintegrity\s*=\s*["\']', tag_attrs, re.IGNORECASE))
                if not has_integrity:
                    missing_sri_scripts.append((src_url, script_host))

    if missing_sri_scripts:
        first_url, first_host = missing_sri_scripts[0]
        hosts_found = list({h for _, h in missing_sri_scripts})
        findings.append(Finding(
            id="missing-sri",
            title="Missing Subresource Integrity (SRI) for Third-Party Scripts",
            severity=Severity.LOW,
            category="Content Security",
            description=(
                f"Found {len(missing_sri_scripts)} third-party script(s) loaded from external host(s) "
                f"({', '.join(hosts_found[:3])}) without cryptographic 'integrity' attributes: {first_url[:75]}..."
            ),
            evidence=f"<script src=\"{first_url}\">",
            impact="If the external third-party host, CDN, or DNS is compromised, attackers can tamper with the script and execute arbitrary JavaScript in visiting users' browsers without detection.",
            remediation="Generate cryptographic sha384 or sha512 hashes and add 'integrity' and 'crossorigin=\"anonymous\"' attributes to all third-party script tags.",
            references=["https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity"]
        ))

    return findings
