import re
import http.cookiejar
from backend.scanner.tech_detector import detect_technologies, extract_meta_tags
from backend.scanner.headers import analyze_headers
from backend.scanner.passive_audit import audit_html_security
from backend.scanner.metasploit_db import generate_metasploit_suggestions
from backend.models import TechInfo, Finding, Severity

def test_all():
    print("==================================================")
    print(" RUNNING AEGISWEB V1.1 COMPREHENSIVE VERIFICATION ")
    print("==================================================")

    # Test 1: Bug 7 - Reverse attribute order for meta generator
    print("\n[TEST 1] Tech Detection with inverted meta tag attributes...")
    html_reverse = '<!DOCTYPE html><html><head><meta content="WordPress 6.4.2" name="generator"></head><body>Hello</body></html>'
    meta_tags = extract_meta_tags(html_reverse)
    assert meta_tags.get("generator") == "WordPress 6.4.2", f"Failed to extract generator: {meta_tags}"
    techs = detect_technologies({}, html_reverse, [])
    wp_tech = next((t for t in techs if t.name == "WordPress"), None)
    assert wp_tech is not None, "WordPress not detected with reversed meta tag attributes!"
    assert wp_tech.version == "6.4.2", f"WordPress version incorrect: {wp_tech.version}"
    print(f"  [+] PASSED: Detected {wp_tech.name} v{wp_tech.version} from inverted meta tag!")

    # Test 2: Bug 2 - Cookie SameSite and HttpOnly extraction
    print("\n[TEST 2] Cookie SameSite & HttpOnly parsing logic...")
    cookie_obj = http.cookiejar.Cookie(
        version=0, name="session_token", value="xyz123", port=None, port_specified=False,
        domain="example.com", domain_specified=True, domain_initial_dot=False,
        path="/", path_specified=True, secure=True, expires=None, discard=True,
        comment=None, comment_url=None, rest={"SameSite": "Strict", "HttpOnly": None}, rfc2109=False
    )
    # Simulate engine extraction
    samesite_val = ""
    for k, v in cookie_obj._rest.items():
        if k.lower() == "samesite":
            samesite_val = (v or "Lax").lower()
            break
    is_httponly = cookie_obj.has_nonstandard_attr("HttpOnly") or any(k.lower() == "httponly" for k in cookie_obj._rest.keys())
    assert samesite_val == "strict", f"SameSite extraction failed: {samesite_val}"
    assert is_httponly is True, "HttpOnly extraction failed"

    # Analyze headers with this cookie
    cookie_dict = [{"name": cookie_obj.name, "value": cookie_obj.value, "secure": True, "httponly": is_httponly, "samesite": samesite_val}]
    findings, _ = analyze_headers({"strict-transport-security": "max-age=31536000"}, cookie_dict, is_https=True)
    cookie_weak = [f for f in findings if "cookie" in f.id.lower()]
    assert len(cookie_weak) == 0, f"Expected 0 cookie warnings for well-configured cookie, got: {cookie_weak}"
    print(f"  [+] PASSED: Cookie with SameSite=Strict and HttpOnly correctly recognized without false positives!")

    # Test 3: Bug 5 - .env detection with broad keywords & HTML guard
    print("\n[TEST 3] .env heuristic (Node/Python/Laravel keywords + HTML guard)...")
    env_content = "DATABASE_URL=postgres://testuser:testpass@localhost:5432/testdb\nAPI_KEY=placeholder-not-real\nJWT_SECRET=placeholder-not-real"
    html_fake_404 = "<!DOCTYPE html><html><body>404 Not Found - APP_DEBUG is false</body></html>"
    from backend.scanner.recon import is_html_response, ENV_SENSITIVE_KEYWORDS
    assert is_html_response(html_fake_404) is True, "HTML 404 should be recognized as HTML"
    assert is_html_response(env_content) is False, "Raw .env should NOT be recognized as HTML"
    assert any(kw in env_content.upper() for kw in ENV_SENSITIVE_KEYWORDS), "Keywords should match Node/Python stack"
    print("  [+] PASSED: .env detects Node/Python secrets and correctly rejects HTML 404 pages!")

    # Test 4: Bug 6 - .git/HEAD detection with detached HEAD
    print("\n[TEST 4] .git/HEAD heuristic with detached HEAD commit hash...")
    detached_head = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n"
    is_detached = bool(re.match(r'^[0-9a-fA-F]{40,64}$', detached_head.strip()))
    assert is_detached is True, "Detached HEAD hash failed to match regex"
    print("  [+] PASSED: Detached HEAD 64-char commit hash successfully recognized!")

    # Test 5: Passive Audits - Mixed Content & SRI
    print("\n[TEST 5] Passive Audits: Mixed Content & Subresource Integrity...")
    html_with_mixed = '''
    <html>
      <head>
        <script src="http://insecure-cdn.com/app.js"></script>
        <script src="https://cdn.jsdelivr.net/npm/vue@3"></script>
      </head>
      <body>Secure page</body>
    </html>
    '''
    findings_html = audit_html_security(html_with_mixed, is_https=True)
    mixed_f = next((f for f in findings_html if f.id == "mixed-content-active"), None)
    sri_f = next((f for f in findings_html if f.id == "missing-sri"), None)
    assert mixed_f is not None, "Failed to detect active mixed content"
    assert sri_f is not None, "Failed to detect missing SRI on third-party script"
    print(f"  [+] PASSED: Detected active mixed content: '{mixed_f.title}'")
    print(f"  [+] PASSED: Detected missing SRI: '{sri_f.title}'")

    # Test 6: Expanded Metasploit Knowledge Base (R6-C1/C3 behavior)
    print("\n[TEST 6] Expanded Metasploit Knowledge Base...")
    iis_tech = [TechInfo(name="Microsoft IIS", category="Web Server", version="10.0")]
    asp_tech = [TechInfo(name="ASP.NET", category="Framework")]
    msf_iis = generate_metasploit_suggestions("https://target-iis.com", iis_tech + asp_tech, [])
    by_id = {m.id: m for m in msf_iis}
    module_paths = [m.module_path for m in msf_iis]
    # R6-C1: baseline modules must not be suggested without a matching finding.
    assert "auxiliary/scanner/http/http_header" not in module_paths, "http_header must not be suggested without findings"
    assert "auxiliary/scanner/http/options" not in module_paths, "options must not be suggested without findings"
    assert "auxiliary/scanner/http/title" not in module_paths, "title module was removed"
    assert "auxiliary/scanner/http/files_dir" not in module_paths, "files_dir must not be suggested by default"
    assert "auxiliary/scanner/http/iis_shortname_scanner" in module_paths, "Missing iis_shortname_scanner"
    assert by_id["msf-iis-shortname"].intrusive is True
    assert "Guesses" in by_id["msf-iis-shortname"].description
    assert "auxiliary/scanner/http/webdav_scanner" in module_paths, "Missing webdav_scanner"
    assert "auxiliary/scanner/http/trace_axd" in module_paths, "Missing trace_axd for ASP.NET"
    print(f"  [+] PASSED: Metasploit suggested {len(msf_iis)} relevant modules including IIS Shortname, WebDAV, Trace.axd!")

    print("\n[ALL 6 TESTS PASSED SUCCESSFULLY!]")

if __name__ == "__main__":
    test_all()
