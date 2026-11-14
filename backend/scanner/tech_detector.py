import re
from typing import Dict, List, Tuple, Optional
from backend.models import TechInfo

def extract_meta_tags(html_text: str) -> Dict[str, str]:
    """
    Extracts meta tags like <meta name="..." content="..."> or <meta content="..." name="...">
    returning a mapping of lowercased name -> content.
    """
    meta_dict = {}
    if not html_text:
        return meta_dict

    meta_pattern = re.compile(r'<meta\b([^>]*)>', re.IGNORECASE)
    name_attr_pattern = re.compile(r'\b(?:name|property)\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE)
    content_attr_pattern = re.compile(r'\bcontent\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE)

    for match in meta_pattern.finditer(html_text):
        tag_content = match.group(1)
        name_match = name_attr_pattern.search(tag_content)
        content_match = content_attr_pattern.search(tag_content)

        if name_match and content_match:
            meta_name = name_match.group(1).strip().lower()
            meta_val = content_match.group(1).strip()
            meta_dict[meta_name] = meta_val

    return meta_dict

TECH_SIGNATURES = [
    # CMS
    {
        "name": "WordPress",
        "category": "CMS",
        "html_patterns": [r"wp-content", r"wp-includes", r"/wp-json/"],
        "generator_regex": r"WordPress\s*([\d\.]*)",
        "header_patterns": {}
    },
    {
        "name": "Joomla",
        "category": "CMS",
        "html_patterns": [r"/media/jui/", r"/media/system/js/"],
        "generator_regex": r"Joomla!?\s*([\d\.]*)",
        "header_patterns": {}
    },
    {
        "name": "Drupal",
        "category": "CMS",
        "html_patterns": [r"/sites/default/files", r"Drupal\.settings"],
        "generator_regex": r"Drupal\s*([\d\.]*)",
        "header_patterns": {"x-generator": r"Drupal\s*([\d\.]*)"}
    },
    {
        "name": "Shopify",
        "category": "E-Commerce",
        "html_patterns": [r"cdn\.shopify\.com", r"Shopify\.theme"],
        "generator_regex": r"Shopify",
        "header_patterns": {}
    },
    {
        "name": "Magento",
        "category": "E-Commerce",
        "html_patterns": [r"Mage\.Cookies", r"skin/frontend"],
        "generator_regex": r"Magento",
        "header_patterns": {}
    },
    
    # Web Servers
    {"name": "Nginx", "category": "Web Server", "html_patterns": [], "header_patterns": {"server": r"nginx(?:/([\d\.]+))?"}},
    {"name": "Apache HTTP Server", "category": "Web Server", "html_patterns": [], "header_patterns": {"server": r"\bApache(?!-Coyote)(?:/([\d\.]+))?"}},
    {"name": "Microsoft IIS", "category": "Web Server", "html_patterns": [], "header_patterns": {"server": r"Microsoft-IIS(?:/([\d\.]+))?"}},
    {"name": "LiteSpeed", "category": "Web Server", "html_patterns": [], "header_patterns": {"server": r"LiteSpeed"}},
    {"name": "Caddy", "category": "Web Server", "html_patterns": [], "header_patterns": {"server": r"Caddy"}},
    {"name": "Apache Tomcat", "category": "Application Server", "html_patterns": [r"Apache Tomcat"], "header_patterns": {"server": r"Apache-Coyote(?:/([\d\.]+))?"}},

    # Programming Languages & Frameworks
    {"name": "PHP", "category": "Programming Language", "html_patterns": [], "header_patterns": {"x-powered-by": r"PHP(?:/([\d\.]+))?"}, "cookie_patterns": [r"PHPSESSID"]},
    {"name": "ASP.NET", "category": "Framework", "html_patterns": [], "header_patterns": {"x-powered-by": r"ASP\.NET", "x-aspnet-version": r"([\d\.]+)"}, "cookie_patterns": [r"ASP\.NET_SessionId", r"ASPSESSIONID"]},
    {"name": "Laravel", "category": "Framework", "html_patterns": [], "header_patterns": {}, "cookie_patterns": [r"laravel_session"]},  # R4-2d: Chỉ laravel_session
    {"name": "Django", "category": "Framework", "html_patterns": [], "header_patterns": {}, "cookie_patterns": [], "require_all_cookies": [r"csrftoken", r"sessionid"]},  # R4-2e: Yêu cầu cả 2
    {"name": "Express.js / Node.js", "category": "Framework", "html_patterns": [], "header_patterns": {"x-powered-by": r"Express"}, "cookie_patterns": [r"connect\.sid"]},
    {"name": "Java / Spring", "category": "Framework", "html_patterns": [], "header_patterns": {}, "cookie_patterns": [r"JSESSIONID"]},
    {"name": "Ruby on Rails", "category": "Framework", "html_patterns": [], "header_patterns": {"x-powered-by": r"Phusion Passenger"}, "cookie_patterns": [r"_session_id"]},

    # CI/CD & DevOps Services
    {"name": "Jenkins", "category": "CI/CD & DevOps", "html_patterns": [r"jenkins-version", r"Jenkins\.instance", r"/static/[a-f0-9]+/images/jenkins"], "header_patterns": {"x-jenkins": r"([\d\.]+)", "x-hudson": r".*"}},
    {"name": "Grafana", "category": "Monitoring & Metrics", "html_patterns": [r"<title>Grafana</title>", r"window\.grafanaBootData", r"/public/build/grafana"], "header_patterns": {}},
    
    # Frontend Libraries
    {"name": "React", "category": "Frontend Framework", "html_patterns": [r"_reactRootContainer", r"data-reactroot", r"react\.production\.min\.js", r"/_next/static/"], "header_patterns": {}},
    {"name": "Next.js", "category": "Frontend Framework", "html_patterns": [r"/_next/static/", r"__NEXT_DATA__"], "header_patterns": {"x-powered-by": r"Next\.js"}},
    {"name": "Vue.js", "category": "Frontend Framework", "html_patterns": [r"data-v-[a-f0-9]+", r"vue\.runtime", r"vue\.min\.js"], "header_patterns": {}},
    {"name": "Nuxt.js", "category": "Frontend Framework", "html_patterns": [r"/_nuxt/", r"__NUXT__"], "header_patterns": {}},
    {"name": "Angular", "category": "Frontend Framework", "html_patterns": [r"ng-version=", r"ng-app="], "header_patterns": {}},
    {"name": "jQuery", "category": "JavaScript Library", "html_patterns": [r"jquery(?:\.min)?\.js(?:\?ver=([\d\.]+))?", r"jQuery v([\d\.]+)"], "header_patterns": {}},
    {"name": "Bootstrap", "category": "UI Framework", "html_patterns": [r"bootstrap(?:\.min)?\.(?:css|js)(?:\?ver=([\d\.]+))?"], "header_patterns": {}},
    {"name": "Tailwind CSS", "category": "UI Framework", "html_patterns": [r"tailwind(?:\.min)?\.css"], "header_patterns": {}},

    # CDN / WAF / Cloud
    {"name": "Cloudflare", "category": "CDN / Reverse Proxy", "html_patterns": [], "header_patterns": {"server": r"cloudflare", "cf-ray": r".*"}},
    {"name": "Amazon CloudFront", "category": "CDN / Cloud", "html_patterns": [], "header_patterns": {"via": r"CloudFront", "x-amz-cf-id": r".*"}},
    {"name": "Fastly", "category": "CDN", "html_patterns": [], "header_patterns": {"x-served-by": r"cache-.*", "fastly-restarts": r".*"}}
]

def detect_technologies(headers: Dict[str, str], body_text: str, cookies: List[Dict[str, str]]) -> List[TechInfo]:
    detected: Dict[str, TechInfo] = {}
    headers_lower = {k.lower(): v for k, v in headers.items()}
    cookie_names = [c.get("name", "") for c in cookies]
    meta_tags = extract_meta_tags(body_text)

    for item in TECH_SIGNATURES:
        name = item["name"]
        category = item["category"]
        found = False
        version = None
        confidence = "Medium"

        # 1. Check Meta Generator
        gen_regex = item.get("generator_regex")
        if gen_regex and "generator" in meta_tags:
            gen_val = meta_tags["generator"]
            match = re.search(gen_regex, gen_val, re.IGNORECASE)
            if match:
                found = True
                confidence = "High"
                if match.groups() and match.group(1):
                    version = match.group(1)

        # 2. Check headers
        if not found:
            for h_key, h_regex in item.get("header_patterns", {}).items():
                if h_key in headers_lower:
                    val = headers_lower[h_key]
                    match = re.search(h_regex, val, re.IGNORECASE)
                    if match:
                        found = True
                        confidence = "High"
                        if match.groups() and match.group(1):
                            version = match.group(1)
                        break

        # 3. Check cookies (Normal)
        if not found:
            for c_regex in item.get("cookie_patterns", []):
                for c_name in cookie_names:
                    if re.search(c_regex, c_name, re.IGNORECASE):
                        found = True
                        confidence = "High"
                        break
                if found:
                    break
        
        # 3b. Check cookies (Require ALL - R4-2e)
        if not found and "require_all_cookies" in item:
            patterns = item["require_all_cookies"]
            matched_all = True
            for pat in patterns:
                if not any(re.search(pat, c_name, re.IGNORECASE) for c_name in cookie_names):
                    matched_all = False
                    break
            if matched_all:
                found = True
                confidence = "High"

        # 4. Check HTML body patterns
        if not found and body_text:
            for pattern in item.get("html_patterns", []):
                match = re.search(pattern, body_text, re.IGNORECASE)
                if match:
                    found = True
                    confidence = "Medium"
                    if match.groups() and match.group(1):
                        version = match.group(1)
                    break

        if found:
            detected[name] = TechInfo(
                name=name,
                category=category,
                version=version,
                confidence=confidence
            )

    return list(detected.values())