from backend.scanner.passive_audit import audit_html_security

def test_fixes():
    print("==================================================")
    print(" VERIFYING PASSIVE_AUDIT.PY 3 TARGETED FIXES      ")
    print("==================================================")

    # 1. Test elif -> if (Both active AND passive mixed content reported)
    print("\n[TEST 1] Verifying elif -> if: Both active and passive mixed content...")
    html_both = '''
    <html>
      <head>
        <script src="http://insecure.org/script.js"></script>
      </head>
      <body>
        <img src="http://insecure.org/image.png" />
      </body>
    </html>
    '''
    findings_both = audit_html_security(html_both, is_https=True, base_url="https://secure-site.com")
    f_ids = [f.id for f in findings_both]
    assert "mixed-content-active" in f_ids, "Failed to report mixed-content-active!"
    assert "mixed-content-passive" in f_ids, "Failed to report mixed-content-passive when both are present!"
    print(f"  [+] PASSED: Both active and passive mixed content reported! Findings: {f_ids}")

    # 2. Test regex link tag attribute order (href before rel vs rel before href)
    print("\n[TEST 2] Verifying <link> tag attribute order-independence...")
    html_links = '''
    <html>
      <head>
        <!-- href before rel -->
        <link href="http://insecure.org/style1.css" rel="stylesheet" />
        <!-- rel before href -->
        <link rel="stylesheet" href="http://insecure.org/style2.css" />
      </head>
      <body>Link test</body>
    </html>
    '''
    findings_links = audit_html_security(html_links, is_https=True, base_url="https://secure-site.com")
    active_f = next((f for f in findings_links if f.id == "mixed-content-active"), None)
    assert active_f is not None, "Failed to detect active mixed content from <link> tags!"
    assert "Found 2 active resource(s)" in active_f.evidence, f"Expected 2 active resources, got: {active_f.evidence}"
    print(f"  [+] PASSED: Both href-first and rel-first <link> tags detected correctly! ({active_f.evidence})")

    # 3. Test SRI expanded dynamically by hostname
    print("\n[TEST 3] Verifying SRI expansion by dynamic hostname...")
    html_sri = '''
    <html>
      <head>
        <!-- Same domain: should NOT require SRI -->
        <script src="https://my-app.com/assets/app.js"></script>
        <!-- Subdomain: should NOT require SRI -->
        <script src="https://cdn.my-app.com/bundle.js"></script>
        <!-- Third-party host without integrity: MUST trigger SRI warning -->
        <script src="https://external-widget.org/tracker.js"></script>
        <!-- Third-party host with integrity: should NOT trigger SRI warning -->
        <script src="https://cdn.example.org/lib.js" integrity="sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4EQY8n5"></script>
      </head>
      <body>SRI test</body>
    </html>
    '''
    findings_sri = audit_html_security(html_sri, is_https=True, base_url="https://my-app.com/home")
    sri_f = next((f for f in findings_sri if f.id == "missing-sri"), None)
    assert sri_f is not None, "Failed to detect missing SRI on third-party host!"
    assert "external-widget.org" in sri_f.description, f"Expected external-widget.org in description, got: {sri_f.description}"
    assert "Found 1 third-party script(s)" in sri_f.description, f"Expected exactly 1 script reported, got: {sri_f.description}"
    print(f"  [+] PASSED: SRI correctly flags third-party host 'external-widget.org' and ignores internal subdomains/existing integrity!")

    print("\n[ALL 3 PASSIVE_AUDIT FIXES VERIFIED SUCCESSFULLY!]")

if __name__ == "__main__":
    test_fixes()
