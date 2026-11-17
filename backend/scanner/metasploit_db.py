import re
import ipaddress
from typing import List, Dict, Any
from urllib.parse import urlparse, quote
from backend.models import MetasploitSuggestion, TechInfo, Finding

METASPLOIT_RULES = [
    # -------------------------------------------------------------
    # FINDING-TRIGGERED BASELINE SCANNERS
    # R6-C1: no "always_suggest" rules. Every suggestion must be tied to a
    # finding or a detected technology, otherwise irrelevant modules appear
    # on every scan.
    # -------------------------------------------------------------
    {
        "id": "msf-http-header",
        "finding_id_match": [
            "missing-strict-transport-security",
            "missing-content-security-policy",
            "missing-x-frame-options",
            "missing-x-content-type-options",
            "missing-referrer-policy",
            "missing-permissions-policy",
        ],
        "module_path": "auxiliary/scanner/http/http_header",
        "module_type": "auxiliary/scanner",
        "title": "HTTP Response Headers Collector",
        "description": "Standardizes and captures all server response headers across various HTTP request variations for verification.",
        "trigger": "Missing security header detected",
        "confidence": "Info",
        "options": {"RHOSTS", "RPORT", "SSL", "TARGETURI"},
        "reference": "https://www.rapid7.com/db/modules/auxiliary/scanner/http/http_header/"
    },
    # R9/R10: msfconsole (`info`, `show options`) identifies this module as
    # "HTTP Options Detection": it sends a single OPTIONS request, has no
    # ACTION option and no write mode. `show options` confirms TARGETURI.
    {
        "id": "msf-options",
        "finding_id_match": ["http-trace-enabled", "http-risky-methods"],
        "module_path": "auxiliary/scanner/http/options",
        "module_type": "auxiliary/scanner",
        "title": "HTTP Options Detection",
        "description": "Displays the HTTP methods the target allows by sending a single OPTIONS request. Read-only: the module has no write mode.",
        "trigger": "HTTP method configuration finding detected",
        "confidence": "Info",
        "options": {"RHOSTS", "RPORT", "SSL", "TARGETURI"},
        "reference": "https://www.rapid7.com/db/modules/auxiliary/scanner/http/options/"
    },
    # R6-C1/C3: only relevant when robots.txt revealed Disallow paths; the
    # module guesses directories, so it is intrusive and hidden by default.
    {
        "id": "msf-dir-scanner",
        "finding_id_match": ["info-robots-txt"],
        "module_path": "auxiliary/scanner/http/dir_scanner",
        "module_type": "auxiliary/scanner",
        "title": "HTTP Directory & Hidden File Scanner",
        "description": "Guesses common directory paths and sends many requests per target to look for unlinked management consoles, staging endpoints, and administrative interfaces. Intrusive: run only with written authorization.",
        "trigger": "robots.txt exposes Disallow paths worth probing",
        "confidence": "Info",
        "intrusive": True,
        # R10-A3: msfconsole rejected TARGETURI for this module ("Unknown
        # datastore option"), so it is not listed here.
        "options": {"RHOSTS", "RPORT", "SSL"},
        "reference": "https://www.rapid7.com/db/modules/auxiliary/scanner/http/dir_scanner/"
    },

    # -------------------------------------------------------------
    # WORDPRESS CMS
    # -------------------------------------------------------------
    {
        "id": "msf-wp-scanner",
        "tech_match": ["WordPress"],
        "module_path": "auxiliary/scanner/http/wordpress_scanner",
        "module_type": "auxiliary/scanner",
        "title": "WordPress Comprehensive Scanner",
        "description": "Performs technology verification, exact core version detection, installed themes, and active plugin enumeration.",
        "trigger": "Detected WordPress CMS",
        "confidence": "High",
        "options": {"RHOSTS", "RPORT", "SSL", "TARGETURI"},
        "reference": "https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_scanner/"
    },
    {
        "id": "msf-wp-pingback",
        "tech_match": ["WordPress"],
        "module_path": "auxiliary/scanner/http/wordpress_pingback_access",
        "module_type": "auxiliary/scanner",
        "title": "WordPress Pingback Port Scanner & SSRF Audit",
        "description": "Audits whether XML-RPC pingback.ping can be abused for SSRF or internal network probing (Warning: sends active outbound requests).",
        "trigger": "Detected WordPress CMS",
        "confidence": "Medium",
        "intrusive": True,
        "options": {"RHOSTS", "RPORT", "SSL", "TARGETURI"},
        "reference": "https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/"
    },

    # -------------------------------------------------------------
    # JOOMLA & DRUPAL CMS
    # -------------------------------------------------------------
    {
        "id": "msf-joomla-ver",
        "tech_match": ["Joomla"],
        "module_path": "auxiliary/scanner/http/joomla_version",
        "module_type": "auxiliary/scanner",
        "title": "Joomla Version Scanner",
        "description": "Accurately determines the precise Joomla version from manifest and core XML files to map CVEs.",
        "trigger": "Detected Joomla CMS",
        "confidence": "High",
        "options": {"RHOSTS", "RPORT", "SSL", "TARGETURI"},
        "reference": "https://www.rapid7.com/db/modules/auxiliary/scanner/http/joomla_version/"
    },
    {
        "id": "msf-drupal-users",
        "tech_match": ["Drupal"],
        "module_path": "auxiliary/scanner/http/drupal_views_user_enum",
        "module_type": "auxiliary/scanner",
        "title": "Drupal Views User Enumeration",
        "description": "Audits Drupal installations for user enumeration vulnerabilities via public Views modules.",
        "trigger": "Detected Drupal CMS",
        "confidence": "Medium",
        "options": {"RHOSTS", "RPORT", "SSL", "TARGETURI"},
        "reference": "https://www.rapid7.com/db/modules/auxiliary/scanner/http/drupal_views_user_enum/"
    },

    # -------------------------------------------------------------
    # MICROSOFT IIS & ASP.NET
    # -------------------------------------------------------------
    {
        "id": "msf-iis-shortname",
        "tech_match": ["Microsoft IIS"],
        "module_path": "auxiliary/scanner/http/iis_shortname_scanner",
        "module_type": "auxiliary/scanner",
        "title": "Microsoft IIS 8.3 Shortname (Tilde) Enumeration",
        "description": "Guesses 8.3 short filenames via ~ character requests and sends many requests per target to discover hidden files and folders. Intrusive: run only with written authorization.",
        "trigger": "Detected Microsoft IIS Server",
        "confidence": "High",
        "intrusive": True,
        # show options: PATH is the base path (no TARGETURI on this module).
        "options": {"RHOSTS", "RPORT", "SSL", "PATH"},
        "reference": "https://www.rapid7.com/db/modules/auxiliary/scanner/http/iis_shortname_scanner/"
    },
    {
        "id": "msf-iis-webdav",
        "tech_match": ["Microsoft IIS"],
        "module_path": "auxiliary/scanner/http/webdav_scanner",
        "module_type": "auxiliary/scanner",
        "title": "HTTP WebDAV Detection & Method Scanner",
        "description": "Tests if WebDAV is enabled on Microsoft IIS or Apache, enumerating PROPFIND/OPTIONS permission states.",
        "trigger": "Detected Microsoft IIS Server",
        "confidence": "Medium",
        # show options: PATH is the path to use (no TARGETURI).
        "options": {"RHOSTS", "RPORT", "SSL", "PATH"},
        "reference": "https://www.rapid7.com/db/modules/auxiliary/scanner/http/webdav_scanner/"
    },
    {
        "id": "msf-iis-internal-ip",
        "tech_match": ["Microsoft IIS"],
        "module_path": "auxiliary/scanner/http/iis_internal_ip",
        "module_type": "auxiliary/scanner",
        "title": "Microsoft IIS Internal IP Disclosure Scanner",
        "description": "Tests Microsoft IIS for internal RFC 1918 private IP address leakage via HTTP 1.0 requests with missing Host headers.",
        "trigger": "Detected Microsoft IIS Server",
        "confidence": "Medium",
        # show options: no path option, only the base three.
        "options": {"RHOSTS", "RPORT", "SSL"},
        "reference": "https://www.rapid7.com/db/modules/auxiliary/scanner/http/iis_internal_ip/"
    },
    {
        "id": "msf-trace-axd",
        "tech_match": ["ASP.NET"],
        "module_path": "auxiliary/scanner/http/trace_axd",
        "module_type": "auxiliary/scanner",
        "title": "ASP.NET Trace.axd Information Leakage Scanner",
        "description": "Audits for unauthenticated access to trace.axd, which exposes detailed session requests, cookies, and physical server paths.",
        "trigger": "Detected ASP.NET Framework",
        "confidence": "High",
        # show options: PATH replaces TARGETURI for this module.
        "options": {"RHOSTS", "RPORT", "SSL", "PATH"},
        "reference": "https://www.rapid7.com/db/modules/auxiliary/scanner/http/trace_axd/"
    },

    # -------------------------------------------------------------
    # APACHE & TOMCAT
    # -------------------------------------------------------------
    {
        "id": "msf-apache-userdir",
        "tech_match": ["Apache HTTP Server"],
        "module_path": "auxiliary/scanner/http/apache_userdir_enum",
        "module_type": "auxiliary/scanner",
        "title": "Apache mod_userdir Username Enumeration",
        "description": "Verifies whether Apache mod_userdir is enabled, allowing enumeration of valid system usernames via /~username/ HTTP responses.",
        "trigger": "Detected Apache HTTP Server",
        "confidence": "Medium",
        "options": {"RHOSTS", "RPORT", "SSL", "TARGETURI"},
        "reference": "https://www.rapid7.com/db/modules/auxiliary/scanner/http/apache_userdir_enum/"
    },
    {
        "id": "msf-tomcat-mgr",
        "tech_match": ["Apache Tomcat"],
        "module_path": "auxiliary/scanner/http/tomcat_mgr_login",
        "module_type": "auxiliary/scanner",
        "title": "Tomcat Application Manager Login Audit",
        "description": "Attempts to discover default or weak credentials on Tomcat Manager (/manager/html) via login brute-force (Warning: attempts logins, potential account lockout).",
        "trigger": "Detected Apache Tomcat / Coyote Server",
        "confidence": "High",
        "intrusive": True,
        # show options: TARGETURI is the Manager login page (/manager/html),
        # not the application root, so the target path is not sent.
        "options": {"RHOSTS", "RPORT", "SSL"},
        "reference": "https://www.rapid7.com/db/modules/auxiliary/scanner/http/tomcat_mgr_login/"
    },
    {
        "id": "msf-tomcat-enum",
        "tech_match": ["Apache Tomcat"],
        "module_path": "auxiliary/scanner/http/tomcat_enum",
        "module_type": "auxiliary/scanner",
        "title": "Apache Tomcat Version & Path Enumerator",
        "description": "Enumerates default servlets, examples, and version disclosure endpoints in Apache Tomcat.",
        "trigger": "Detected Apache Tomcat",
        "confidence": "High",
        # show options: TARGETURI is the admin login page
        # (/admin/j_security_check), not the application root.
        "options": {"RHOSTS", "RPORT", "SSL"},
        "reference": "https://www.rapid7.com/db/modules/auxiliary/scanner/http/tomcat_enum/"
    },

    # -------------------------------------------------------------
    # DEVOPS & INFRASTRUCTURE SERVICES (Jenkins, Grafana)
    # -------------------------------------------------------------
    {
        "id": "msf-jenkins-enum",
        "tech_match": ["Jenkins"],
        "module_path": "auxiliary/scanner/http/jenkins_enum",
        "module_type": "auxiliary/scanner",
        "title": "Jenkins CI/CD Enumeration Scanner",
        "description": "Enumerates unauthenticated Jenkins instances to gather version information, job configurations, build metadata, and installed plugin versions.",
        "trigger": "Detected Jenkins CI/CD instance",
        "confidence": "High",
        "options": {"RHOSTS", "RPORT", "SSL", "TARGETURI"},
        "reference": "https://www.rapid7.com/db/modules/auxiliary/scanner/http/jenkins_enum/"
    },
    {
        "id": "msf-grafana-audit",
        "tech_match": ["Grafana"],
        "module_path": "auxiliary/scanner/http/grafana_plugin_traversal",
        "module_type": "auxiliary/scanner",
        "title": "Grafana Plugins Path Traversal Scanner (CVE-2021-43798)",
        "description": "Audits unauthenticated Grafana installations for vulnerable plugin asset endpoints vulnerable to arbitrary file reading.",
        "trigger": "Detected Grafana Monitoring Dashboard",
        "confidence": "High",
        "options": {"RHOSTS", "RPORT", "SSL", "TARGETURI"},
        "reference": "https://www.rapid7.com/db/modules/auxiliary/scanner/http/grafana_plugin_traversal/"
    },

    # -------------------------------------------------------------
    # FINDING-TRIGGERED RULES
    # -------------------------------------------------------------
    {
        "id": "msf-git-scanner",
        "finding_id_match": ["exposed-git-head"],
        "module_path": "auxiliary/scanner/http/git_scanner",
        "module_type": "auxiliary/scanner",
        "title": "Git Source Repository Metadata Scanner",
        "description": "Verifies accessibility and enumerates exposed Git repositories and object packs on HTTP servers.",
        "trigger": "Publicly exposed .git repository found",
        "confidence": "High",
        # show options: TARGETURI points at the .git directory (default
        # /.git/), not the application root, so the target path is not sent.
        "options": {"RHOSTS", "RPORT", "SSL"},
        "reference": "https://www.rapid7.com/db/modules/auxiliary/scanner/http/git_scanner/"
    },
    {
        "id": "msf-robots-scanner",
        "finding_id_match": ["info-robots-txt"],
        "module_path": "auxiliary/scanner/http/robots_txt",
        "module_type": "auxiliary/scanner",
        "title": "Robots.txt Analysis & Disallowed Path Scanner",
        "description": "Automatically retrieves and systematically audits paths declared in robots.txt for accessibility and sensitive content.",
        "trigger": "robots.txt file discovered on target",
        "confidence": "High",
        # show options: PATH is the path used to locate robots.txt.
        "options": {"RHOSTS", "RPORT", "SSL", "PATH"},
        "reference": "https://www.rapid7.com/db/modules/auxiliary/scanner/http/robots_txt/"
    },
    {
        "id": "msf-ssl-version",
        "finding_id_match": ["ssl-deprecated-protocol-TLSv1", "ssl-deprecated-protocol-TLSv1.1", "ssl-verification-failed"],
        "module_path": "auxiliary/scanner/ssl/ssl_version",
        "module_type": "auxiliary/scanner",
        "title": "SSL/TLS Cipher Suite & Protocol Version Scanner",
        "description": "Performs comprehensive enumeration of supported SSL/TLS versions and weak ciphers (RC4, 3DES, CBC).",
        "trigger": "Weak or deprecated SSL/TLS configuration detected",
        "confidence": "High",
        "reference": "https://www.rapid7.com/db/modules/auxiliary/scanner/ssl/ssl_version/"
    }
]

def generate_metasploit_suggestions(
    target_url: str,
    technologies: List[TechInfo],
    findings: List[Finding]
) -> List[MetasploitSuggestion]:
    try:
        parsed = urlparse(target_url)
    except Exception:
        return []

    raw_host = parsed.hostname or "127.0.0.1"
    cleaned_host = raw_host.strip("[]")  # Bỏ ngoặc IPv6
    
    # R4-7: Validate hostname (IPv4/Domain hoặc IPv6)
    is_valid = False
    if re.match(r"^[A-Za-z0-9.-]+$", cleaned_host):
        is_valid = True
    else:
        try:
            ipaddress.ip_address(cleaned_host)
            is_valid = True
        except ValueError:
            pass
            
    if not is_valid:
        return []
        
    hostname = cleaned_host  # Dùng cleaned_host cho RHOSTS

    is_ssl = (parsed.scheme == "https")
    try:
        port = parsed.port or (443 if is_ssl else 80)
    except ValueError:
        port = 443 if is_ssl else 80

    raw_path = parsed.path if parsed.path and parsed.path != "/" else "/"
    target_uri = quote(raw_path, safe="/-_.~%?=&")

    tech_names = {t.name.lower() for t in technologies}
    finding_ids = {f.id for f in findings}

    suggestions: List[MetasploitSuggestion] = []
    # R6-C2: de-duplicate per rule id so a rule cannot be suggested twice.
    seen_rule_ids = set()

    for rule in METASPLOIT_RULES:
        if rule["id"] in seen_rule_ids:
            continue

        module_path = rule["module_path"]
        matched = False
        trigger_reason = rule.get("trigger", "Auditing recommendation")

        if "tech_match" in rule:
            for tm in rule["tech_match"]:
                if tm.lower() in tech_names:
                    matched = True
                    trigger_reason = f"Detected technology: {tm}"
                    break

        if not matched and "finding_id_match" in rule:
            for fm in rule["finding_id_match"]:
                if fm in finding_ids:
                    matched = True
                    matching_finding = next((f for f in findings if f.id == fm), None)
                    if matching_finding:
                        trigger_reason = f"Triggered by finding: {matching_finding.title}"
                    break

        if matched:
            seen_rule_ids.add(rule["id"])
            
            ssl_flag = "true" if is_ssl else "false"
            # R10-A1/R11: emit only options the rule declares. Missing
            # "options" means the safe default RHOSTS/RPORT/SSL. TARGETURI and
            # PATH are added only for modules where "show options" confirmed
            # the option and its meaning matches the target's application path.
            rule_options = rule.get("options")
            if rule_options is None:
                rule_options = {"RHOSTS", "RPORT", "SSL"}
            option_fragments = (
                f"set RHOSTS {hostname}; "
                f"set RPORT {port}; "
                f"set SSL {ssl_flag}; "
            )
            if "TARGETURI" in rule_options:
                option_fragments += f"set TARGETURI {target_uri}; "
            if "PATH" in rule_options:
                option_fragments += f"set PATH {target_uri}; "
            cmd = (
                f'msfconsole -q -x "use {module_path}; '
                f'{option_fragments}'
                f'run; exit"'
            )

            suggestions.append(MetasploitSuggestion(
                id=rule["id"],
                module_path=module_path,
                module_type=rule["module_type"],
                title=rule["title"],
                description=rule["description"],
                trigger_reason=trigger_reason,
                confidence=rule.get("confidence", "Medium"),
                verification_command=cmd,
                references=[rule["reference"]] if "reference" in rule else [],
                intrusive=rule.get("intrusive", False)
            ))

    return suggestions