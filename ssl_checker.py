import socket
import ssl
from datetime import datetime, timezone
from typing import Tuple, List, Optional
from urllib.parse import urlparse

from backend.models import SSLInfo, Finding, Severity

def parse_ssl_date(date_str: str) -> Optional[datetime]:
    formats = [
        "%b %d %H:%M:%S %Y %Z",
        "%b  %d %H:%M:%S %Y %Z",
    ]
    for fmt in formats:
        try:
            return datetime.strptime(date_str, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None

def check_ssl(target_url: str, timeout: int = 5) -> Tuple[Optional[SSLInfo], List[Finding]]:
    parsed = urlparse(target_url)
    hostname = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    
    findings: List[Finding] = []
    
    # If explicit HTTP was requested without port 443, test if HTTPS is available
    if parsed.scheme == "http" and port == 80:
        findings.append(Finding(
            id="unencrypted-http",
            title="Unencrypted HTTP Protocol In Use",
            severity=Severity.HIGH,
            category="Transport Security",
            description="The site was accessed over unencrypted plain HTTP (port 80).",
            evidence=f"URL: {target_url}",
            impact="All traffic, passwords, and sensitive session tokens are transmitted in plaintext and can be intercepted or modified by network eavesdroppers.",
            remediation="Enforce HTTPS with automatic 301 redirection from HTTP to HTTPS.",
            references=["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/03-Testing_for_Sensitive_Information_Sent_via_Unencrypted_Channels"]
        ))
        port = 443 # also probe 443 to check if SSL is configured

    ssl_info = SSLInfo(has_ssl=False)

    try:
        context = ssl.create_default_context()
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED

        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                tls_version = ssock.version()

                ssl_info.has_ssl = True
                ssl_info.valid = True
                ssl_info.tls_version = tls_version
                ssl_info.cipher = f"{cipher[0]} ({cipher[1]})" if cipher else "Unknown"

                # Parse issuer & subject
                issuer_dict = dict(x[0] for x in cert.get("issuer", ()))
                subject_dict = dict(x[0] for x in cert.get("subject", ()))
                ssl_info.issuer = issuer_dict.get("organizationName") or issuer_dict.get("commonName") or "Unknown"
                ssl_info.subject = subject_dict.get("commonName") or "Unknown"

                # Parse SANs
                san_list = [entry[1] for entry in cert.get("subjectAltName", ()) if entry[0] == "DNS"]
                ssl_info.san = san_list

                # Parse dates
                not_before = cert.get("notBefore")
                not_after = cert.get("notAfter")
                ssl_info.not_before = not_before
                ssl_info.not_after = not_after

                if not_after:
                    expiry_date = parse_ssl_date(not_after)
                    if expiry_date:
                        now = datetime.now(timezone.utc)
                        days_left = (expiry_date - now).days
                        ssl_info.expires_in_days = days_left

                        if days_left < 0:
                            ssl_info.valid = False
                            findings.append(Finding(
                                id="ssl-expired",
                                title="SSL/TLS Certificate Expired",
                                severity=Severity.CRITICAL,
                                category="SSL/TLS",
                                description=f"The certificate expired {abs(days_left)} days ago.",
                                evidence=f"Expired on: {not_after}",
                                impact="Browsers display prominent security warnings, preventing users from accessing the site and eroding trust.",
                                remediation="Renew and install an active SSL certificate immediately.",
                                references=["https://www.ssllabs.com/"]
                            ))
                        elif days_left < 30:
                            findings.append(Finding(
                                id="ssl-expiring-soon",
                                title=f"SSL/TLS Certificate Expiring Soon ({days_left} Days)",
                                severity=Severity.MEDIUM,
                                category="SSL/TLS",
                                description=f"The certificate will expire in {days_left} days.",
                                evidence=f"Expires on: {not_after}",
                                impact="Site will trigger security warnings if not renewed before expiration.",
                                remediation="Renew the certificate before the expiration date.",
                                references=["https://www.ssllabs.com/"]
                            ))

                # TLS Protocol Check
                if tls_version in ["TLSv1", "TLSv1.1", "SSLv2", "SSLv3"]:
                    findings.append(Finding(
                        id=f"ssl-deprecated-protocol-{tls_version}",
                        title=f"Deprecated TLS Protocol ({tls_version})",
                        severity=Severity.HIGH,
                        category="SSL/TLS",
                        description=f"Server supports obsolete protocol {tls_version}, which is vulnerable to known cryptographic attacks (e.g., POODLE, BEAST).",
                        evidence=f"Negotiated: {tls_version}",
                        impact="Potential decryption or tampering with encrypted communications.",
                        remediation="Disable SSLv2, SSLv3, TLS 1.0, and TLS 1.1 on the server. Support TLS 1.2 and TLS 1.3 only.",
                        references=["https://datatracker.ietf.org/doc/html/rfc8996"]
                    ))

    except ssl.SSLCertVerificationError as e:
        ssl_info.has_ssl = True
        ssl_info.valid = False
        ssl_info.warnings.append(str(e))
        findings.append(Finding(
            id="ssl-verification-failed",
            title="SSL Certificate Verification Failed",
            severity=Severity.HIGH,
            category="SSL/TLS",
            description=f"SSL certificate validation failed: {str(e)}",
            evidence=str(e),
            impact="Users will see dangerous security warnings. High susceptibility to Man-in-the-Middle attacks if self-signed or improperly chained.",
            remediation="Install a valid SSL certificate issued by a trusted Certificate Authority (e.g. Let's Encrypt).",
            references=["https://letsencrypt.org/"]
        ))
    except (socket.timeout, socket.gaierror, ConnectionRefusedError, OSError) as e:
        ssl_info.warnings.append(f"Connection error: {str(e)}")

    return ssl_info, findings
