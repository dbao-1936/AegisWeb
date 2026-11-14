import re
import httpx
from typing import List, Dict, Any, Tuple
from urllib.parse import urljoin
from backend.models import Finding, Severity

SAFE_ENDPOINTS = [
    {
        "path": "/robots.txt",
        "name": "Robots Exclusion Protocol",
        "description": "Checks for robots.txt which may disclose sensitive endpoints or administrative paths."
    },
    {
        "path": "/sitemap.xml",
        "name": "XML Sitemap",
        "description": "Checks for sitemap.xml revealing full route topology."
    },
    {
        "path": "/.well-known/security.txt",
        "name": "Security Contact Information",
        "description": "Checks for security.txt describing vulnerability disclosure policies."
    },
    {
        "path": "/.git/HEAD",
        "name": "Git Repository Exposure",
        "description": "Checks if the .git metadata directory is accidentally exposed to the public."
    },
    {
        "path": "/.env",
        "name": "Environment Configuration File",
        "description": "Checks if environment variables with secrets or database credentials are exposed."
    }
]

# Sensitive keywords commonly found in environment configuration files
ENV_SENSITIVE_KEYWORDS = [
    "DATABASE_URL", "DB_CONNECTION", "DB_PASSWORD", "DB_HOST", "DB_USERNAME",
    "APP_KEY", "APP_SECRET", "SECRET_KEY", "API_KEY", "AWS_ACCESS_KEY",
    "AWS_SECRET", "STRIPE_KEY", "STRIPE_SECRET", "JWT_SECRET", "PRIVATE_KEY",
    "REDIS_PASSWORD", "MAIL_PASSWORD", "TOKEN", "AUTH0"
]

def is_html_response(text: str) -> bool:
    """Detect if response is an HTML page (e.g. customized 404/login page returning 200)."""
    sample = text[:500].lower()
    return "<!doctype html" in sample or "<html" in sample or "<head" in sample or "<body" in sample

MAX_BODY_BYTES = 8192

def redact_env_keys(text: str) -> str:
    """Return only KEY=<redacted> names for KEY=value lines (never raw values)."""
    keys: List[str] = []
    for line in text.splitlines():
        match = re.match(r'^\s*([A-Za-z0-9_]{2,})\s*=', line)
        if match and match.group(1) not in keys:
            keys.append(match.group(1))
    return "\n".join(f"{key}=<redacted>" for key in keys)

async def fetch_limited(client: httpx.AsyncClient, url: str, timeout: float) -> Tuple[int, str]:
    """GET url and read at most MAX_BODY_BYTES, returning (status_code, decoded_text)."""
    async with client.stream("GET", url, timeout=timeout, follow_redirects=False) as resp:
        chunks: List[bytes] = []
        total = 0
        async for chunk in resp.aiter_bytes():
            if not chunk:
                continue
            remaining = MAX_BODY_BYTES - total
            if remaining <= 0:
                break
            piece = chunk[:remaining]
            chunks.append(piece)
            total += len(piece)
            if total >= MAX_BODY_BYTES:
                break

        raw = b"".join(chunks)
        encoding = resp.encoding or "utf-8"
        try:
            text = raw.decode(encoding, errors="replace")
        except LookupError:
            text = raw.decode("utf-8", errors="replace")
        return resp.status_code, text

async def check_recon_endpoints(client: httpx.AsyncClient, base_url: str) -> Tuple[List[Dict[str, Any]], List[Finding]]:
    recon_results: List[Dict[str, Any]] = []
    findings: List[Finding] = []

    for item in SAFE_ENDPOINTS:
        target_path = item["path"]
        full_url = urljoin(base_url, target_path)

        try:
            status_code, resp_text = await fetch_limited(client, full_url, 5.0)
            content_sample = resp_text[:200].strip()

            is_accessible = (status_code == 200)

            # Never expose raw .env values: only allow-listed key names are stored.
            content_preview = content_sample if is_accessible else None
            if target_path == "/.env" and is_accessible:
                redacted = redact_env_keys(resp_text)
                content_preview = redacted if redacted else None

            result_entry = {
                "path": target_path,
                "url": full_url,
                "status_code": status_code,
                "accessible": is_accessible,
                "name": item["name"],
                "content_preview": content_preview
            }
            recon_results.append(result_entry)

            # 1. robots.txt
            if target_path == "/robots.txt" and is_accessible and not is_html_response(resp_text):
                disallow_lines = [line.strip() for line in resp_text.splitlines() if line.lower().startswith("disallow:")]
                findings.append(Finding(
                    id="info-robots-txt",
                    title="Public robots.txt File Discovered",
                    severity=Severity.INFO,
                    category="Information Disclosure",
                    description=f"Found public robots.txt containing {len(disallow_lines)} Disallow rule(s).",
                    evidence=f"Disallow count: {len(disallow_lines)}\nSample: {', '.join(disallow_lines[:3])}",
                    impact="Disallow directives may highlight interesting administrative or internal endpoints to potential attackers.",
                    remediation="Ensure robots.txt does not leak sensitive or secret directory paths.",
                    references=["https://developers.google.com/search/docs/crawling-indexing/robots/intro"]
                ))

            # 2. security.txt
            elif target_path == "/.well-known/security.txt" and not is_accessible:
                findings.append(Finding(
                    id="missing-security-txt",
                    title="Missing security.txt Policy",
                    severity=Severity.INFO,
                    category="Best Practices",
                    description="No security.txt file found under /.well-known/security.txt.",
                    evidence=f"HTTP {status_code}",
                    impact="Security researchers may lack a clear, secure contact channel to report discovered vulnerabilities responsibly.",
                    remediation="Create a /.well-known/security.txt file adhering to RFC 9116.",
                    references=["https://securitytxt.org/"]
                ))

            # 3. .git/HEAD check (Supports ref: and detached HEAD commit hash; guards against HTML 404s)
            elif target_path == "/.git/HEAD" and is_accessible:
                is_html = is_html_response(resp_text)
                stripped = resp_text.strip()
                has_ref = "ref:" in stripped
                has_commit_hash = bool(re.match(r'^[0-9a-fA-F]{40,64}$', stripped))

                if not is_html and (has_ref or has_commit_hash):
                    findings.append(Finding(
                        id="exposed-git-head",
                        title="Exposed .git Source Code Repository",
                        severity=Severity.CRITICAL,
                        category="Sensitive Data Exposure",
                        description="The server publicly exposes the .git repository metadata directory (HEAD).",
                        evidence=f"GET /.git/HEAD -> {content_sample[:60]}",
                        impact="Attackers can download the entire source code history, commit logs, internal architecture, and hardcoded secrets.",
                        remediation="Block public web server access to dotfiles (e.g., in Nginx: 'location ~ /\\.git { deny all; }', in Apache: '<DirectoryMatch \"/\\.git\"> Require all denied </DirectoryMatch>').",
                        references=["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/05-Review_Webpage_Content_for_Information_Leakage"]
                    ))

            # 4. .env check (Broad heuristic: multiple KEY=val lines OR known secret keys; guards against HTML 404s)
            elif target_path == "/.env" and is_accessible:
                is_html = is_html_response(resp_text)
                if not is_html:
                    # Count KEY=val lines
                    kv_lines = [
                        line.strip() for line in resp_text.splitlines() 
                        if re.match(r'^[A-Za-z0-9_]{2,}\s*=\s*.+$', line.strip())
                    ]
                    has_known_keyword = any(kw in resp_text.upper() for kw in ENV_SENSITIVE_KEYWORDS)

                    if len(kv_lines) >= 2 or (len(kv_lines) >= 1 and has_known_keyword):
                        findings.append(Finding(
                            id="exposed-env-file",
                            title="Critical Exposure of .env Environment Secrets",
                            severity=Severity.CRITICAL,
                            category="Sensitive Data Exposure",
                            description="The server publicly exposes the raw .env configuration file containing sensitive parameters and secrets.",
                            evidence=f"Found {len(kv_lines)} config definitions. Sample key(s): {', '.join([l.split('=')[0] for l in kv_lines[:3]])}",
                            impact="Database passwords, API keys, and encryption secrets are completely exposed to anyone on the internet.",
                            remediation="Configure the web server to block all requests to '.env' files and ensure environment secrets are placed outside the web root.",
                            references=["https://cwe.mitre.org/data/definitions/552.html"]
                        ))

        except Exception:
            recon_results.append({
                "path": target_path,
                "url": full_url,
                "status_code": 0,
                "accessible": False,
                "name": item["name"],
                "content_preview": None
            })

    # 5. Verbose Error Page / Stack Trace Detection
    # Probe a random non-existent path to test error page sanitization
    try:
        err_url = urljoin(base_url, "/_aegis_sec_probe_404_test_endpoint")
        _, err_body = await fetch_limited(client, err_url, 4.0)

        verbose_indicators = [
            ("Traceback (most recent call last)", "Python Stack Trace"),
            ("Fatal error:", "PHP Fatal Error"),
            ("Exception in thread", "Java Exception"),
            ("at org.apache.catalina", "Tomcat Internal Trace"),
            ("System.NullReferenceException", ".NET Exception"),
            ("DEBUG = True", "Django/Flask Debug Mode"),
            ("Whoops! There was an error", "Laravel Whoops Debugger")
        ]

        for phrase, label in verbose_indicators:
            if phrase.lower() in err_body.lower():
                findings.append(Finding(
                    id="verbose-error-page",
                    title=f"Verbose Error Page / Internal Disclosure ({label})",
                    severity=Severity.MEDIUM,
                    category="Information Disclosure",
                    description=f"Server returned a verbose error page disclosing sensitive internal execution details ({label}).",
                    evidence=f"GET /_aegis_sec_probe_404_test_endpoint -> Matches '{phrase}'",
                    impact="Discloses backend filesystem structure, database queries, framework internals, or line numbers to attackers.",
                    remediation="Disable debug mode in production (e.g. DEBUG=False, display_errors=Off). Implement custom friendly 404/500 error pages.",
                    references=["https://owasp.org/www-community/Improper_Error_Handling"]
                ))
                break
    except Exception:
        pass

    return recon_results, findings
