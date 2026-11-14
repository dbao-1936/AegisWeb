"""
Subdomain Intelligence Module
Step 1: Passive subdomain discovery (crt.sh + DNS resolution)
Step 2: Wildcard DNS detection
Step 3: Subdomain takeover fingerprinting (including dangling CNAMEs without A records)
Step 4: DNS/Email security checks on registrable apex domain (SPF, DMARC, DKIM, CAA, DNSSEC)
"""
import asyncio
import re
import socket
import random
import string
import logging
from typing import List, Dict, Optional, Tuple, Any
from datetime import datetime, timezone
from urllib.parse import urlparse

import aiohttp
import dns.resolver
import dns.flags
import dns.exception
import dns.rdatatype
import tldextract

from backend.models import Finding, Severity

logger = logging.getLogger("aegisweb.subdomain_recon")


# ---------------------------------------------------------------------------
# Registrable Domain Helper
# ---------------------------------------------------------------------------
_tld_extractor = tldextract.TLDExtract(suffix_list_urls=None)

def get_registrable_domain(domain_or_url: str) -> str:
    clean = domain_or_url.strip().lower()
    if clean.startswith(("http://", "https://")):
        clean = urlparse(clean).hostname or clean
    clean = re.sub(r'^www\.', '', clean)
    extracted = _tld_extractor(clean)
    if extracted.domain and extracted.suffix:
        return f"{extracted.domain}.{extracted.suffix}"
    return clean


# ---------------------------------------------------------------------------
# Subdomain Takeover Fingerprints
# ---------------------------------------------------------------------------
TAKEOVER_SIGNATURES: List[Dict[str, Any]] = [
    {
        "service": "GitHub Pages",
        "cname_patterns": [r"github\.io$", r"github\.com$"],
        "error_patterns": ["There isn't a GitHub Pages site here", "For root URLs (like http://example.com/) you must provide an index.html"],
        "expected_status": [404],
        "severity": Severity.CRITICAL,
    },
    {
        "service": "Amazon S3",
        "cname_patterns": [r"s3\.amazonaws\.com$", r"s3-[a-z0-9-]+\.amazonaws\.com$"],
        "error_patterns": ["NoSuchBucket", "The specified bucket does not exist"],
        "expected_status": [404],
        "severity": Severity.CRITICAL,
    },
    {
        "service": "Amazon CloudFront",
        "cname_patterns": [r"cloudfront\.net$"],
        "error_patterns": ["ERROR: The request could not be satisfied"],
        "expected_status": [403, 404],
        "severity": Severity.HIGH,
    },
    {
        "service": "Heroku",
        "cname_patterns": [r"herokudns\.com$", r"herokudns\.com", r"herokussl\.com$", r"\.heroku\.com$"],
        "error_patterns": ["No such app", "herokucdn.com/error-pages/no-such-app.html", "There's nothing here, yet."],
        "expected_status": [404, 502, 503],
        "severity": Severity.CRITICAL,
    },
    {
        "service": "Netlify",
        "cname_patterns": [r"netlify\.app$", r"netlify\.com$"],
        "error_patterns": ["Not found - Request ID:"],
        "expected_status": [404],
        "severity": Severity.HIGH,
    },
    {
        "service": "Vercel",
        "cname_patterns": [r"vercel\.app$", r"now\.sh$"],
        "error_patterns": ["The deployment you are looking for does not exist", "404: NOT_FOUND"],
        "expected_status": [404],
        "severity": Severity.HIGH,
    },
    {
        "service": "Fastly",
        "cname_patterns": [r"fastly\.net$"],
        "error_patterns": ["Fastly error: unknown domain:", "Please check that this domain has been added to a service"],
        "expected_status": [404, 500],
        "severity": Severity.HIGH,
    },
    {
        "service": "Shopify",
        "cname_patterns": [r"myshopify\.com$", r"shops\.myshopify\.com$"],
        "error_patterns": ["Sorry, this shop is currently unavailable.", "Sorry, this store is currently unavailable."],
        "expected_status": [404],
        "severity": Severity.MEDIUM,
    },
    {
        "service": "Microsoft Azure",
        "cname_patterns": [r"azurewebsites\.net$", r"cloudapp\.net$", r"azureedge\.net$", r"blob\.core\.windows\.net$"],
        "error_patterns": ["404 Web Site not found.", "Sorry, this site is unavailable", "The resource you are looking for has been removed"],
        "expected_status": [404],
        "severity": Severity.CRITICAL,
    },
    {
        "service": "Ghost",
        "cname_patterns": [r"ghost\.io$"],
        "error_patterns": ["404 - Domain Not Found"],
        "expected_status": [404],
        "severity": Severity.MEDIUM,
    },
    {
        "service": "Tumblr",
        "cname_patterns": [r"tumblr\.com$"],
        "error_patterns": ["Whatever you were looking for doesn't currently exist at this address"],
        "expected_status": [404],
        "severity": Severity.HIGH,
    },
    {
        "service": "Zendesk",
        "cname_patterns": [r"zendesk\.com$"],
        "error_patterns": ["Help Center Closed"],
        "expected_status": [404],
        "severity": Severity.MEDIUM,
    },
    {
        "service": "HubSpot",
        "cname_patterns": [r"hubspot\.net$", r"hubspot\.com$"],
        "error_patterns": ["Domain not found in HubSpot"],
        "expected_status": [404],
        "severity": Severity.MEDIUM,
    },
]


# ---------------------------------------------------------------------------
# DNS Resolver helpers (R4-6: Status Tracking)
# ---------------------------------------------------------------------------
def _sync_resolve_status(hostname: str, record_type: str) -> Tuple[List[str], str]:
    """Returns (answers, status) where status is 'ok', 'nodata', 'nxdomain', 'error'."""
    try:
        answers = dns.resolver.resolve(hostname, record_type, lifetime=4.0)
        return [str(r) for r in answers], "ok"
    except dns.resolver.NXDOMAIN:
        return [], "nxdomain"
    except dns.resolver.NoAnswer:
        return [], "nodata"
    except Exception:
        return [], "error"

def _sync_resolve(hostname: str, record_type: str) -> List[str]:
    answers, _ = _sync_resolve_status(hostname, record_type)
    return answers

async def resolve_async(hostname: str, record_type: str) -> List[str]:
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, _sync_resolve, hostname, record_type)

async def resolve_status_async(hostname: str, record_type: str) -> Tuple[List[str], str]:
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, _sync_resolve_status, hostname, record_type)


def _sync_check_dnssec(domain: str) -> bool:
    try:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = ["1.1.1.1", "8.8.8.8"]
        resolver.use_edns(0, dns.flags.DO, 1232)
        answer = resolver.resolve(domain, "A", lifetime=4.0)
        if bool(answer.response.flags & dns.flags.AD):
            return True
        try:
            ds = resolver.resolve(domain, "DS", lifetime=3.0)
            if ds:
                return True
        except Exception:
            pass
        return False
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Step 1: Passive Subdomain Discovery via crt.sh
# ---------------------------------------------------------------------------
async def fetch_subdomains_crtsh(domain: str, timeout: int = 12) -> Tuple[List[str], Optional[str]]:
    query = f"%.{domain}"
    url = f"https://crt.sh/?q={query}&output=json"
    logger.info("Querying crt.sh: %s", url)
    subdomains = set()
    error_msg = None
    subdomains.add(domain)

    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=timeout)) as resp:
                if resp.status == 200:
                    try:
                        data = await resp.json(content_type=None)
                        if isinstance(data, list):
                            for entry in data:
                                name_value = entry.get("name_value", "")
                                for sub in name_value.splitlines():
                                    sub = sub.strip().lower().lstrip("*.")
                                    if sub.endswith(f".{domain}") or sub == domain:
                                        subdomains.add(sub)
                        else:
                            error_msg = f"Unexpected response format from crt.sh: {type(data).__name__}"
                    except Exception as json_err:
                        error_msg = f"Failed to parse JSON from crt.sh: {str(json_err)}"
                else:
                    error_msg = f"crt.sh returned HTTP status {resp.status}"
    except asyncio.TimeoutError:
        error_msg = f"crt.sh request timed out after {timeout}s (service may be congested)"
    except Exception as e:
        error_msg = f"Failed to connect to crt.sh: {str(e)}"

    if error_msg:
        logger.warning("crt.sh query error for domain %s: %s", domain, error_msg)

    return sorted(subdomains), error_msg


# ---------------------------------------------------------------------------
# Step 2: Wildcard DNS Detection
# ---------------------------------------------------------------------------
async def detect_wildcard_dns(domain: str) -> Optional[List[str]]:
    random_label = ''.join(random.choices(string.ascii_lowercase, k=12))
    probe_host = f"{random_label}.{domain}"
    ips = await resolve_async(probe_host, "A")
    return ips if ips else None


def _sync_ptr(ip: str) -> Optional[str]:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Step 3: Resolve each subdomain and check liveness
# ---------------------------------------------------------------------------
async def resolve_subdomain_info(subdomain: str) -> Dict[str, Any]:
    a_records = await resolve_async(subdomain, "A")
    cname_records = await resolve_async(subdomain, "CNAME")

    ptr = None
    if a_records:
        loop = asyncio.get_running_loop()
        ptr = await loop.run_in_executor(None, _sync_ptr, a_records[0])

    is_alive = bool(a_records)
    return {
        "subdomain": subdomain,
        "ip_addresses": a_records,
        "cname": cname_records[0].rstrip(".") if cname_records else None,
        "ptr": ptr,
        "alive": is_alive,
    }


# ---------------------------------------------------------------------------
# Step 4: Subdomain Takeover Detection (Dangling CNAME + Fingerprint)
# ---------------------------------------------------------------------------
async def check_takeover(subdomain_info: Dict[str, Any], http_session: aiohttp.ClientSession) -> Optional[Finding]:
    cname = subdomain_info.get("cname") or ""
    subdomain = subdomain_info["subdomain"]
    is_wildcard = subdomain_info.get("wildcard_filtered", False)
    ips = subdomain_info.get("ip_addresses") or []

    if not cname:
        return None

    # H1/R4-6: Dangling CNAME path (require nxdomain status)
    if not ips:
        target_a, status = await resolve_status_async(cname, "A")
        if status == "nxdomain":  # R4-6: Only report on confirmed NXDOMAIN
            for sig in TAKEOVER_SIGNATURES:
                for pattern in sig["cname_patterns"]:
                    if re.search(pattern, cname, re.IGNORECASE):
                        wildcard_note = " (Note: Subdomain resides in a wildcard DNS zone)" if is_wildcard else ""
                        return Finding(
                            id=f"subdomain-takeover-{subdomain}",
                            title=f"Possible Subdomain Takeover — Dangling CNAME ({sig['service']}) on {subdomain}{wildcard_note}",
                            severity=sig["severity"],
                            category="Subdomain Takeover",
                            description=(
                                f"The subdomain '{subdomain}' has a CNAME pointing to '{cname}' ({sig['service']}), "
                                f"but the target host does not resolve to any IP address (NXDOMAIN). "
                                f"This dangling pointer indicates the remote resource was deleted or unclaimed."
                            ),
                            evidence=f"CNAME: {subdomain} → {cname}; target has no A record (NXDOMAIN)",
                            impact=(
                                f"An attacker can register the unclaimed resource on {sig['service']} "
                                f"and gain control of '{subdomain}' to serve malicious content or steal cookies."
                            ),
                            remediation=(
                                f"Remove the dangling CNAME record for '{subdomain}' immediately, "
                                f"or re-create/reclaim the resource on {sig['service']}."
                            ),
                            references=[
                                "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/10-Test_for_Subdomain_Takeover",
                                "https://github.com/EdOverflow/can-i-take-over-xyz",
                            ]
                        )
            return None

    # HTTP fingerprint check
    for sig in TAKEOVER_SIGNATURES:
        matched_service = False
        for pattern in sig["cname_patterns"]:
            if re.search(pattern, cname, re.IGNORECASE):
                matched_service = True
                break

        if not matched_service:
            continue

        expected_statuses = sig.get("expected_status", [404])

        for scheme in ("https", "http"):
            url = f"{scheme}://{subdomain}"
            try:
                async with http_session.get(
                    url,
                    timeout=aiohttp.ClientTimeout(total=6),
                    allow_redirects=True,
                    ssl=False,
                ) as resp:
                    if resp.status not in expected_statuses:
                        continue

                    body = await resp.text(encoding="utf-8", errors="ignore")
                    body_lower = body.lower()

                    for error_phrase in sig["error_patterns"]:
                        if error_phrase.lower() in body_lower:
                            wildcard_note = " (Note: Subdomain resides in a wildcard DNS zone)" if is_wildcard else ""
                            return Finding(
                                id=f"subdomain-takeover-{subdomain}",
                                title=f"Possible Subdomain Takeover — {sig['service']} ({subdomain}){wildcard_note}",
                                severity=sig["severity"],
                                category="Subdomain Takeover",
                                description=(
                                    f"The subdomain '{subdomain}' has a CNAME record pointing to "
                                    f"'{cname}' ({sig['service']}), but the target service "
                                    f"returned HTTP {resp.status} indicating the resource is unclaimed or missing."
                                ),
                                evidence=(
                                    f"CNAME: {subdomain} → {cname}\n"
                                    f"HTTP {resp.status} on {url}: matched error phrase '{error_phrase}'"
                                ),
                                impact=(
                                    "An attacker can register the unclaimed resource on the third-party "
                                    f"service ({sig['service']}) and serve arbitrary content from "
                                    f"'{subdomain}', potentially stealing cookies, credentials, or "
                                    "performing phishing attacks under the trusted domain name."
                                ),
                                remediation=(
                                    f"Remove the dangling CNAME record for '{subdomain}' from DNS "
                                    "immediately, or reclaim the resource on the third-party service. "
                                    "Regularly audit CNAME records pointing to external services."
                                ),
                                references=[
                                    "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/10-Test_for_Subdomain_Takeover",
                                    "https://github.com/EdOverflow/can-i-take-over-xyz",
                                ]
                            )
            except Exception:
                continue

    return None


# ---------------------------------------------------------------------------
# Step 5: DNS/Email Security Checks
# ---------------------------------------------------------------------------
async def check_dns_email_security(registrable_domain: str) -> List[Finding]:
    findings: List[Finding] = []
    domain = registrable_domain

    # SPF
    txt_records = await resolve_async(domain, "TXT")
    spf_records = [r for r in txt_records if "v=spf1" in r.lower()]

    if not spf_records:
        findings.append(Finding(
            id="dns-missing-spf",
            title=f"Missing SPF Record on Apex Domain ({domain})",
            severity=Severity.MEDIUM,
            category="DNS / Email Security",
            description=f"No SPF (Sender Policy Framework) TXT record found for '{domain}'.",
            evidence=f"DNS TXT query on {domain} returned no SPF record",
            impact="Attackers can spoof email From: headers using your domain to send phishing or spam emails that appear to originate from your organisation.",
            remediation='Add a TXT record: "v=spf1 mx include:_spf.yourmailprovider.com ~all". Use -all for strict reject.',
            references=["https://datatracker.ietf.org/doc/html/rfc7208", "https://mxtoolbox.com/spf.aspx"]
        ))
    else:
        spf_val = spf_records[0]
        if "+all" in spf_val:
            findings.append(Finding(
                id="dns-spf-plus-all",
                title=f"SPF Record Uses '+all' on {domain} (Allows Any Sender)",
                severity=Severity.HIGH,
                category="DNS / Email Security",
                description=f"SPF record contains '+all' which authorises ANY server to send email on behalf of '{domain}'.",
                evidence=f"SPF: {spf_val}",
                impact="Provides zero protection against email spoofing — completely negates the purpose of SPF.",
                remediation='Replace "+all" with "~all" (soft fail) or "-all" (hard reject).',
                references=["https://datatracker.ietf.org/doc/html/rfc7208"]
            ))
        elif "?all" in spf_val:
            findings.append(Finding(
                id="dns-spf-question-all",
                title=f"SPF Record Uses '?all' on {domain} (Neutral — No Policy)",
                severity=Severity.LOW,
                category="DNS / Email Security",
                description=f"SPF record ends with '?all', meaning receivers take no action against unauthorised senders.",
                evidence=f"SPF: {spf_val}",
                impact="Weak SPF policy. Spoofed emails may not be rejected.",
                remediation='Change "?all" to "~all" or "-all".',
                references=["https://datatracker.ietf.org/doc/html/rfc7208"]
            ))

    # DMARC
    dmarc_records = await resolve_async(f"_dmarc.{domain}", "TXT")
    dmarc_val = next((r for r in dmarc_records if "v=dmarc1" in r.lower()), None)

    if not dmarc_val:
        findings.append(Finding(
            id="dns-missing-dmarc",
            title=f"Missing DMARC Record on Apex Domain ({domain})",
            severity=Severity.MEDIUM,
            category="DNS / Email Security",
            description=f"No DMARC record found at '_dmarc.{domain}'.",
            evidence=f"DNS TXT query on _dmarc.{domain} returned no DMARC record",
            impact="Without DMARC, receiving mail servers have no policy guidance for handling SPF/DKIM failures. Domain spoofing emails reach recipients' inboxes.",
            remediation=f'Add a TXT record at _dmarc.{domain}: "v=DMARC1; p=quarantine; rua=mailto:dmarc@{domain}".',
            references=["https://datatracker.ietf.org/doc/html/rfc7489", "https://dmarc.org/"]
        ))
    else:
        p_match = re.search(r'\bp\s*=\s*(\w+)', dmarc_val, re.IGNORECASE)
        if p_match:
            policy = p_match.group(1).lower()
            if policy == "none":
                findings.append(Finding(
                    id="dns-dmarc-policy-none",
                    title=f"DMARC Policy Set to 'none' on {domain} (No Enforcement)",
                    severity=Severity.LOW,
                    category="DNS / Email Security",
                    description=f"DMARC record exists but policy is 'p=none', meaning only monitoring with no email enforcement or rejection.",
                    evidence=f"DMARC: {dmarc_val}",
                    impact="Spoofed emails still reach recipients. The 'none' policy provides reporting data only — no actual protection.",
                    remediation='Upgrade DMARC policy: "p=quarantine" (mark as spam) or "p=reject" (block outright).',
                    references=["https://dmarc.org/2016/01/how-to-upgrade-your-dmarc-policy/"]
                ))

    # DKIM (R4-13: Stricter check)
    common_selectors = ["default", "google", "selector1", "selector2", "k1"]
    found_dkim = False
    for sel in common_selectors:
        dkim_recs = await resolve_async(f"{sel}._domainkey.{domain}", "TXT")
        for r in dkim_recs:
            r_lower = r.lower()
            # R4-13: Require v=dkim1 OR (k=rsa AND p=)
            if "v=dkim1" in r_lower or ("k=rsa" in r_lower and "p=" in r_lower):
                found_dkim = True
                break
        if found_dkim:
            break
            
    if not found_dkim:
        findings.append(Finding(
            id="dns-no-common-dkim",
            title=f"No DKIM Record Found Among Common Selectors on {domain}",
            severity=Severity.INFO,
            category="DNS / Email Security",
            description=(
                f"No DKIM (DomainKeys Identified Mail) public key record was found at common selector names "
                f"({', '.join(common_selectors)}) for '{domain}'."
            ),
            evidence=f"Queried common selector patterns at <selector>._domainkey.{domain}",
            impact=(
                "DKIM cryptographic email signatures verify sender authenticity and prevent email tampering in transit. "
                "If a custom selector name is used, this info alert can be disregarded."
            ),
            remediation="Ensure DKIM is configured for outgoing mail servers and public keys published under selector._domainkey.",
            references=["https://datatracker.ietf.org/doc/html/rfc6376"]
        ))

    # CAA
    caa_records = await resolve_async(domain, "CAA")
    if not caa_records:
        findings.append(Finding(
            id="dns-missing-caa",
            title=f"Missing CAA Record on Apex Domain ({domain})",
            severity=Severity.INFO,
            category="DNS / Email Security",
            description=f"No CAA record found for '{domain}'.",
            evidence=f"DNS CAA query on {domain} returned no records",
            impact="Without a CAA record, any Certificate Authority (CA) on the internet is authorised to issue SSL/TLS certificates for your domain.",
            remediation='Add a CAA record: 0 issue "letsencrypt.org" (restrict to only trusted CAs you use).',
            references=["https://datatracker.ietf.org/doc/html/rfc6844", "https://sslmate.com/caa/"]
        ))

    # DNSSEC
    loop = asyncio.get_running_loop()
    has_dnssec = await loop.run_in_executor(None, _sync_check_dnssec, domain)

    if not has_dnssec:
        findings.append(Finding(
            id="dns-no-dnssec",
            title=f"DNSSEC Not Enabled or Validated on {domain}",
            severity=Severity.INFO,
            category="DNS / Email Security",
            description=f"DNSSEC validation flag (AD) was not set for '{domain}'.",
            evidence="DNSSEC Authentic Data (AD) flag not present in DNS response",
            impact="Without DNSSEC, DNS responses can be forged or manipulated by DNS cache poisoning attacks, redirecting users to attacker-controlled servers.",
            remediation=f"Enable DNSSEC signing at your domain registrar and DNS provider, then verify with: dig +dnssec {domain}",
            references=["https://datatracker.ietf.org/doc/html/rfc4035", "https://www.icann.org/resources/pages/dnssec-what-is-it-why-important-2019-03-05-en"]
        ))

    return findings


# ---------------------------------------------------------------------------
# Main Subdomain Recon Orchestrator
# ---------------------------------------------------------------------------
async def run_subdomain_recon(domain: str, max_concurrent: int = 8, timeout: int = 12) -> Dict[str, Any]:
    max_concurrent = min(max(1, max_concurrent), 20)

    registrable_domain = get_registrable_domain(domain)
    now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    result: Dict[str, Any] = {
        "domain": domain,
        "registrable_domain": registrable_domain,
        "scan_time": now_utc,
        "source": "crt.sh (Certificate Transparency)",
        "wildcard_ips": None,
        "is_wildcard": False,
        "crtsh_error": None,
        "subdomains": [],
        "takeover_findings": [],
        "dns_findings": [],
        "total_discovered": 0,
        "total_alive": 0,
    }

    # 1. Passive discovery
    raw_subdomains, crtsh_error = await fetch_subdomains_crtsh(domain, timeout=timeout)
    result["total_discovered"] = len(raw_subdomains)
    result["crtsh_error"] = crtsh_error

    # 2. Wildcard DNS detection
    wildcard_ips = await detect_wildcard_dns(domain)
    if wildcard_ips:
        result["is_wildcard"] = True
        result["wildcard_ips"] = wildcard_ips

    # 3. Resolve subdomains concurrently
    semaphore = asyncio.Semaphore(max_concurrent)

    async def resolve_with_limit(sub: str) -> Dict[str, Any]:
        async with semaphore:
            info = await resolve_subdomain_info(sub)
            if wildcard_ips and all(ip in wildcard_ips for ip in info["ip_addresses"]) and info["ip_addresses"]:
                info["wildcard_filtered"] = True
            else:
                info["wildcard_filtered"] = False
            return info

    resolved = await asyncio.gather(*[resolve_with_limit(s) for s in raw_subdomains])
    result["subdomains"] = resolved
    result["total_alive"] = sum(1 for s in resolved if s["alive"] and not s["wildcard_filtered"])

    # 4. Takeover checks (R4-1: Fix assignment logic)
    takeover_findings: List[Finding] = []
    candidates = [s for s in resolved if s.get("cname")]

    if candidates:
        connector = aiohttp.TCPConnector(ssl=False)
        async with aiohttp.ClientSession(connector=connector) as session:
            sem_takeover = asyncio.Semaphore(5)

            async def check_with_limit(sub_info: Dict) -> Optional[Finding]:
                async with sem_takeover:
                    return await check_takeover(sub_info, session)

            takeover_results = await asyncio.gather(*[check_with_limit(c) for c in candidates])
            # R4-1: Use takeover_results, not takeover_findings
            takeover_findings = [f for f in takeover_results if f is not None]

    result["takeover_findings"] = [f.model_dump() for f in takeover_findings]

    # 5. DNS/Email security checks
    dns_findings = await check_dns_email_security(registrable_domain)
    result["dns_findings"] = [f.model_dump() for f in dns_findings]

    return result