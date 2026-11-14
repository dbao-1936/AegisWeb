import asyncio
from backend.models import ScanRequest
from backend.scanner.headers import analyze_headers
from backend.scanner.tech_detector import detect_technologies
from backend.scanner.metasploit_db import generate_metasploit_suggestions

def run_tests():
    print("[-] Testing Header analysis...")
    mock_headers = {
        'server': 'Apache/2.4.41 (Ubuntu)',
        'x-powered-by': 'PHP/7.4.3'
    }
    findings, status = analyze_headers(mock_headers, [], False)
    print(f"    [+] Findings generated: {len(findings)}")
    for f in findings[:3]:
        print(f"        - [{f.severity}] {f.title}")

    print("[-] Testing Tech detection...")
    techs = detect_technologies(mock_headers, '<html><meta name="generator" content="WordPress 5.8"></html>', [])
    print(f"    [+] Detected {len(techs)} technologies: {[t.name for t in techs]}")

    print("[-] Testing Metasploit suggestion mapping...")
    msf = generate_metasploit_suggestions('http://example.com', techs, findings)
    print(f"    [+] Suggested {len(msf)} modules:")
    for m in msf:
        print(f"        * [{m.module_path}] Trigger: {m.trigger_reason}")
        print(f"          Command: {m.verification_command}")

    print("\n[SUCCESS] All unit tests completed without errors!")

if __name__ == "__main__":
    run_tests()
