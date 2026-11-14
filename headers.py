from typing import Dict, List, Tuple, Any
from backend.models import Finding, Severity

SECURITY_HEADERS_DEFINITION = {
    "strict-transport-security": {
        "title": "Missing Strict-Transport-Security (HSTS) Header",
        "severity": Severity.MEDIUM,
        "category": "Security Headers",
        "impact": "Browser may connect via unencrypted HTTP on initial requests, making traffic vulnerable to Man-In-The-Middle (MitM) and SSL Stripping attacks.",
        "remediation": "Configure HTTP Strict Transport Security: 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload'",
        "references": ["https://owasp.org/www-project-secure-headers/#strict-transport-security"]
    },
    "content-security-policy": {
        "title": "Missing Content-Security-Policy (CSP) Header",
        "severity": Severity.MEDIUM,
        "category": "Security Headers",
        "impact": "Without CSP, the browser cannot restrict resource loading origins, significantly increasing the risk and impact of Cross-Site Scripting (XSS) and data injection.",
        "remediation": "Implement a restrictive CSP header defining trusted sources for scripts, styles, images, and frame ancestors. Example: \"default-src 'self'; script-src 'self'\"",
        "references": ["https://owasp.org/www-project-secure-headers/#content-security-policy"]
    },
    "x-frame-options": {
        "title": "Missing X-Frame-Options Header",
        "severity": Severity.MEDIUM,
        "category": "Security Headers",
        "impact": "The website can be embedded in an <iframe> on external malicious websites, leading to Clickjacking (UI redressing) attacks.",
        "remediation": "Add 'X-Frame-Options: DENY' or 'X-Frame-Options: SAMEORIGIN', or use CSP 'frame-ancestors'.",
        "references": ["https://owasp.org/www-project-secure-headers/#x-frame-options"]
    },
    "x-content-type-options": {
        "title": "Missing X-Content-Type-Options Header",
        "severity": Severity.LOW,
        "category": "Security Headers",
        "impact": "Browsers may attempt to MIME-sniff the content type away from the declared Content-Type, potentially executing user-uploaded non-executable files as scripts.",
        "remediation": "Add 'X-Content-Type-Options: nosniff' header.",
        "references": ["https://owasp.org/www-project-secure-headers/#x-content-type-options"]
    },
    "referrer-policy": {
        "title": "Missing Referrer-Policy Header",
        "severity": Severity.LOW,
        "category": "Security Headers",
        "impact": "Sensitive query parameters, internal paths, or tokens in the URL may be leaked to external sites via the Referer header.",
        "remediation": "Configure 'Referrer-Policy: strict-origin-when-cross-origin' or 'no-referrer'.",
        "references": ["https://owasp.org/www-project-secure-headers/#referrer-policy"]
    },
    "permissions-policy": {
        "title": "Missing Permissions-Policy Header",
        "severity": Severity.INFO,
        "category": "Security Headers",
        "impact": "Browser features and APIs (e.g., camera, microphone, geolocation) are not explicitly restricted for embedded third-party frames.",
        "remediation": "Specify allowed browser features using 'Permissions-Policy: camera=(), microphone=(), geolocation=()'.",
        "references": ["https://owasp.org/www-project-secure-headers/#permissions-policy"]
    }
}

def analyze_headers(headers: Dict[str, str], cookies: List[Dict[str, Any]], is_https: bool) -> Tuple[List[Finding], Dict[str, Any]]:
    findings: List[Finding] = []
    headers_lower = {k.lower(): v for k, v in headers.items()}
    header_status: Dict[str, Any] = {}

    # 1. Check Standard Security Headers
    for header_name, meta in SECURITY_HEADERS_DEFINITION.items():
        if header_name in headers_lower:
            val = headers_lower[header_name]
            header_status[header_name] = {"present": True, "value": val}
            
            # Special check for CSP weak configurations
            if header_name == "content-security-policy":
                if "unsafe-inline" in val or "unsafe-eval" in val:
                    findings.append(Finding(
                        id=f"csp-unsafe-directive",
                        title="Weak Content-Security-Policy (Unsafe Directives)",
                        severity=Severity.LOW,
                        category="Security Headers",
                        description="CSP policy contains 'unsafe-inline' or 'unsafe-eval', weakening script execution boundaries.",
                        evidence=f"CSP: {val}",
                        impact="Reduces protection against XSS attacks.",
                        remediation="Use nonces or hashes instead of 'unsafe-inline' and refactor code to avoid 'unsafe-eval'.",
                        references=["https://csp-evaluator.withgoogle.com/"]
                    ))
            # Special check for HSTS max-age
            elif header_name == "strict-transport-security":
                if "max-age" in val:
                    try:
                        max_age_part = [p for p in val.split(";") if "max-age" in p][0]
                        seconds = int(max_age_part.split("=")[1].strip())
                        if seconds < 10368000: # ~120 days
                            findings.append(Finding(
                                id="hsts-low-max-age",
                                title="HSTS max-age Too Short",
                                severity=Severity.LOW,
                                category="Security Headers",
                                description=f"HSTS max-age is set to {seconds} seconds. Recommended minimum is at least 31536000 (1 year).",
                                evidence=f"HSTS: {val}",
                                impact="Short HSTS duration reduces the window of forced secure communication.",
                                remediation="Increase max-age to 31536000 (1 year) and consider 'includeSubDomains; preload'.",
                                references=["https://hstspreload.org/"]
                            ))
                    except Exception:
                        pass
        else:
            header_status[header_name] = {"present": False, "value": None}
            # Only complain about HSTS if target is HTTPS
            if header_name == "strict-transport-security" and not is_https:
                continue
                
            findings.append(Finding(
                id=f"missing-{header_name}",
                title=meta["title"],
                severity=meta["severity"],
                category=meta["category"],
                description=f"The HTTP response is missing the '{header_name}' header.",
                evidence=None,
                impact=meta["impact"],
                remediation=meta["remediation"],
                references=meta["references"]
            ))

    # 2. Information Disclosure in Headers (Server banner, X-Powered-By)
    for leak_header in ["server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"]:
        if leak_header in headers_lower:
            val = headers_lower[leak_header]
            # Check if version numbers or detailed tech are disclosed
            has_version = any(char.isdigit() for char in val)
            severity = Severity.LOW if has_version else Severity.INFO
            
            findings.append(Finding(
                id=f"disclosure-{leak_header}",
                title=f"Technology Banner Disclosure ({leak_header.title()})",
                severity=severity,
                category="Information Disclosure",
                description=f"Server exposes technology/version details via the '{leak_header}' header.",
                evidence=f"{leak_header}: {val}",
                impact="Attackers can tailor exploits against known vulnerabilities of the specific disclosed software and version.",
                remediation=f"Mask or remove the '{leak_header}' header in web server configuration (e.g. 'ServerTokens Prod' in Apache, 'server_tokens off;' in Nginx).",
                references=["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server"]
            ))

    # 3. Analyze Cookies
    for cookie in cookies:
        name = cookie.get("name", "Unknown")
        is_secure = cookie.get("secure", False)
        is_httponly = cookie.get("httponly", False)
        samesite = cookie.get("samesite", "").lower()

        if is_https and not is_secure:
            findings.append(Finding(
                id=f"cookie-no-secure-{name}",
                title=f"Cookie Without Secure Flag ({name})",
                severity=Severity.MEDIUM,
                category="Cookie Security",
                description=f"The cookie '{name}' was set without the 'Secure' attribute.",
                evidence=f"Cookie: {name}",
                impact="Cookie may be transmitted over unencrypted HTTP channels, exposing session tokens to eavesdropping.",
                remediation=f"Set 'Secure' attribute for cookie '{name}'.",
                references=["https://owasp.org/www-community/controls/SecureFlag"]
            ))

        if not is_httponly:
            findings.append(Finding(
                id=f"cookie-no-httponly-{name}",
                title=f"Cookie Without HttpOnly Flag ({name})",
                severity=Severity.LOW,
                category="Cookie Security",
                description=f"The cookie '{name}' was set without the 'HttpOnly' attribute.",
                evidence=f"Cookie: {name}",
                impact="If the application suffers from XSS, attackers can read this cookie via document.cookie.",
                remediation=f"Set 'HttpOnly' attribute for session cookie '{name}'.",
                references=["https://owasp.org/www-community/HttpOnly"]
            ))

        # SameSite verification
        if not samesite:
            findings.append(Finding(
                id=f"cookie-missing-samesite-{name}",
                title=f"Cookie Missing SameSite Attribute ({name})",
                severity=Severity.LOW,
                category="Cookie Security",
                description=f"The cookie '{name}' does not specify a SameSite attribute.",
                evidence=f"Cookie: {name}",
                impact="Without explicit SameSite attribute, the cookie may rely on browser default behavior, increasing exposure to Cross-Site Request Forgery (CSRF).",
                remediation=f"Explicitly configure 'SameSite=Lax' or 'SameSite=Strict' for cookie '{name}'.",
                references=["https://owasp.org/www-community/SameSite"]
            ))
        elif samesite == "none" and not is_secure:
            findings.append(Finding(
                id=f"cookie-insecure-samesite-none-{name}",
                title=f"Insecure SameSite=None Without Secure Flag ({name})",
                severity=Severity.MEDIUM,
                category="Cookie Security",
                description=f"The cookie '{name}' sets SameSite=None without the Secure attribute.",
                evidence=f"Cookie: {name}; SameSite=None",
                impact="Modern browsers reject cookies configured with SameSite=None unless the Secure flag is also present.",
                remediation=f"Always add the 'Secure' flag when setting SameSite=None on cookie '{name}'.",
                references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite"]
            ))
        elif samesite == "none":
            findings.append(Finding(
                id=f"cookie-samesite-none-{name}",
                title=f"Cookie Configured With SameSite=None ({name})",
                severity=Severity.INFO,
                category="Cookie Security",
                description=f"The cookie '{name}' is explicitly configured with SameSite=None.",
                evidence=f"Cookie: {name}; SameSite=None",
                impact="SameSite=None permits the cookie to be sent on cross-site requests, which is necessary for third-party widgets but risky for primary session cookies.",
                remediation=f"Ensure cookie '{name}' is not an authentication or session token. If it is, switch to 'SameSite=Lax' or 'SameSite=Strict'.",
                references=["https://owasp.org/www-community/SameSite"]
            ))

    return findings, header_status
