import os
import sys
import tempfile
import asyncio

# Isolated test DB
temp_db_file = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
temp_db_path = temp_db_file.name
temp_db_file.close()
os.environ["AEGISWEB_DB"] = temp_db_path

from backend.database import (
    init_db, save_scan, load_scan, list_scans,
    get_previous_scan, compute_scan_diff,
    save_recon, load_recon, list_recons,
    get_previous_recon, compute_recon_diff,
    log_consent, get_db
)
from backend.scanner.tech_detector import detect_technologies
from backend.scanner.metasploit_db import generate_metasploit_suggestions
from backend.scanner.subdomain_recon import (
    get_registrable_domain, fetch_subdomains_crtsh, check_takeover,
    _sync_check_dnssec
)
from backend.scanner.normalize import normalize_domain, validate_domain
from backend.scanner.recon import check_recon_endpoints, fetch_limited, MAX_BODY_BYTES
from backend.models import TechInfo, Finding, Severity
from urllib.parse import urlparse

from unittest.mock import AsyncMock, MagicMock, patch


class _FakeReconResponse:
    def __init__(self, status_code, body):
        self.status_code = status_code
        self._body = body
        self.encoding = "utf-8"
        self.headers = {"content-type": "text/plain"}

    async def aiter_bytes(self):
        yield self._body


class _FakeReconStream:
    def __init__(self, response):
        self._response = response

    async def __aenter__(self):
        return self._response

    async def __aexit__(self, exc_type, exc, tb):
        return False


class _FakeReconClient:
    """Minimal httpx.AsyncClient stand-in exposing client.stream()."""

    def __init__(self, responses):
        self._responses = responses

    def stream(self, method, url, **kwargs):
        path = urlparse(url).path
        status_code, body = self._responses.get(path, (404, b""))
        return _FakeReconStream(_FakeReconResponse(status_code, body))

def test_all():
    print("==================================================")
    print(" RUNNING AEGISWEB V1.2.1 COMPREHENSIVE TEST SUITE ")
    print("==================================================")

    try:
        init_db()

        # TEST 1: SQLite & Diff
        print("\n[TEST 1] SQLite isolation & Scan Diff...")
        scan_1 = {
            "scan_id": "scan_001", "target_url": "https://test-host.com", "hostname": "test-host.com",
            "scan_time": "2026-10-24 10:00:00 UTC", "duration_seconds": 1.2, "status": "completed",
            "summary": {"score": 75, "grade": "C", "total_findings": 2, "critical": 0, "high": 1, "medium": 1, "low": 0, "info": 0},
            "findings": [
                {"id": "missing-csp", "title": "Missing CSP", "severity": "MEDIUM", "category": "Headers", "description": "", "impact": "", "remediation": ""},
                {"id": "ssl-weak", "title": "Weak SSL", "severity": "HIGH", "category": "SSL", "description": "", "impact": "", "remediation": ""}
            ],
            "headers_analyzed": {"content-security-policy": {"present": False}},
            "ssl_info": {"expires_in_days": 120}
        }
        save_scan(scan_1)
        scan_2 = {
            "scan_id": "scan_002", "target_url": "https://test-host.com", "hostname": "test-host.com",
            "scan_time": "2026-10-25 10:00:00 UTC", "duration_seconds": 1.1, "status": "completed",
            "summary": {"score": 85, "grade": "B", "total_findings": 2, "critical": 0, "high": 0, "medium": 1, "low": 1, "info": 0},
            "findings": [
                {"id": "missing-csp", "title": "Missing CSP", "severity": "MEDIUM", "category": "Headers", "description": "", "impact": "", "remediation": ""},
                {"id": "missing-xcto", "title": "Missing XCTO", "severity": "LOW", "category": "Headers", "description": "", "impact": "", "remediation": ""}
            ],
            "headers_analyzed": {"content-security-policy": {"present": False}, "x-content-type-options": {"present": False}},
            "ssl_info": {"expires_in_days": 119}
        }
        prev = get_previous_scan("test-host.com")
        assert prev is not None and prev["scan_id"] == "scan_001"
        diff = compute_scan_diff(scan_2, prev)
        assert diff["score_delta"] == 10
        assert len(diff["new_findings"]) == 1 and diff["new_findings"][0]["id"] == "missing-xcto"
        assert len(diff["resolved_findings"]) == 1 and diff["resolved_findings"][0]["id"] == "ssl-weak"
        print(f"  [+] PASSED: Score delta +{diff['score_delta']}")

        # TEST 2: Recon Diff
        print("\n[TEST 2] Recon Diff & scan_time...")
        recon_1 = {"domain": "acme-corp.com", "total_discovered": 2, "total_alive": 2, "subdomains": [{"subdomain": "api.acme-corp.com"}, {"subdomain": "app.acme-corp.com"}], "takeover_findings": [], "dns_findings": []}
        save_recon("r_001", "acme-corp.com", recon_1)
        loaded_r1 = load_recon("r_001")
        assert "scan_time" in loaded_r1
        recon_2 = {"domain": "acme-corp.com", "total_discovered": 3, "total_alive": 2, "subdomains": [{"subdomain": "api.acme-corp.com"}, {"subdomain": "dev.acme-corp.com"}], "takeover_findings": [{"id": "to-dev", "title": "Subdomain Takeover on dev"}], "dns_findings": []}
        prev_r = get_previous_recon("acme-corp.com")
        r_diff = compute_recon_diff(recon_2, prev_r)
        assert "dev.acme-corp.com" in r_diff["new_subdomains"]
        assert "app.acme-corp.com" in r_diff["removed_subdomains"]
        assert len(r_diff["new_takeovers"]) == 1
        print("  [+] PASSED")

        # TEST 3: Consent
        print("\n[TEST 3] Consent Logging...")
        log_consent("example.com", "127.0.0.1", True)
        with get_db() as conn:
            c = conn.cursor()
            c.execute("SELECT domain, client_ip, consent FROM consent_logs WHERE domain='example.com'")
            c_row = c.fetchone()
            assert c_row is not None and c_row["consent"] == 1
        print("  [+] PASSED")

        # TEST 4: Apache Regex
        print("\n[TEST 4] Apache Regex...")
        techs_coyote = detect_technologies({"server": "Apache-Coyote/1.1"}, "", [])
        tech_names_coyote = [t.name for t in techs_coyote]
        assert "Apache Tomcat" in tech_names_coyote
        assert "Apache HTTP Server" not in tech_names_coyote
        techs_apache = detect_technologies({"server": "Apache/2.4.52 (Ubuntu)"}, "", [])
        assert "Apache HTTP Server" in [t.name for t in techs_apache]
        print("  [+] PASSED")

        # TEST 5: Registrable Domain
        print("\n[TEST 5] Registrable Domain...")
        assert get_registrable_domain("sinhvien.huit.edu.vn") == "huit.edu.vn"
        assert get_registrable_domain("sub.example.com") == "example.com"
        assert get_registrable_domain("localhost") == "localhost"
        print("  [+] PASSED")

        # TEST 6: Normalize & Validate (R4-4)
        print("\n[TEST 6] Normalize & Validate...")
        assert normalize_domain("www.example.com") == "example.com"
        assert normalize_domain("wow.com") == "wow.com"
        assert normalize_domain("http://www.test.com/path?q=1") == "test.com"
        assert normalize_domain("example.com/foo") == "example.com"
        assert normalize_domain("example.com:8080") == "example.com"
        assert normalize_domain("  EXAMPLE.COM  ") == "example.com"
        
        assert validate_domain("example.com") is True
        assert validate_domain("localhost") is False
        assert validate_domain("192.168.1.1") is False
        assert validate_domain("::1") is False
        assert validate_domain("example") is False
        assert validate_domain("a..b.com") is False
        print("  [+] PASSED")

        # TEST 7: Takeover Mock (R4-4)
        print("\n[TEST 7] Takeover Mock...")
        asyncio.run(test_takeover_with_mock())
        print("  [+] PASSED")

        # TEST 8: DevSecOps & Metasploit
        print("\n[TEST 8] DevSecOps & Metasploit...")
        techs_jenkins = detect_technologies({"x-jenkins": "2.319.1"}, "", [])
        techs_grafana = detect_technologies({}, "<html><head><title>Grafana</title><script>window.grafanaBootData={}</script></head></html>", [])
        all_techs = techs_jenkins + techs_grafana
        msf_suggestions = generate_metasploit_suggestions("https://ops.example.com", all_techs, [])
        module_paths = [m.module_path for m in msf_suggestions]
        assert "auxiliary/scanner/http/jenkins_enum" in module_paths
        assert "auxiliary/scanner/http/grafana_plugin_traversal" in module_paths
        print("  [+] PASSED")

        # TEST 9: .env secret redaction (R5-A)
        print("\n[TEST 9] .env secret redaction...")
        env_body = b"DB_PASSWORD=hunter2\nSECRET_KEY=topsecret\nAPP_ENV=production\n"
        redact_results, redact_findings = asyncio.run(
            check_recon_endpoints(_FakeReconClient({"/.env": (200, env_body)}), "https://env-check.example")
        )
        env_entry = next(r for r in redact_results if r["path"] == "/.env")
        assert env_entry["accessible"] is True
        assert env_entry["content_preview"] is not None
        assert "DB_PASSWORD=<redacted>" in env_entry["content_preview"]
        assert "hunter2" not in env_entry["content_preview"]
        assert "topsecret" not in env_entry["content_preview"]
        assert all("hunter2" not in (r.get("content_preview") or "") for r in redact_results)
        assert all("hunter2" not in (f.evidence or "") for f in redact_findings)
        print("  [+] PASSED")

        # TEST 10: response body cap (R5-B)
        print("\n[TEST 10] Response body cap...")
        big_body = b"A" * MAX_BODY_BYTES + b"TAIL_MARKER" * 512
        cap_client = _FakeReconClient({"/robots.txt": (200, big_body)})
        cap_status, capped_text = asyncio.run(
            fetch_limited(cap_client, "https://cap-check.example/robots.txt", 5.0)
        )
        assert cap_status == 200
        assert len(capped_text) == MAX_BODY_BYTES
        assert "TAIL_MARKER" not in capped_text

        cap_results, _ = asyncio.run(check_recon_endpoints(cap_client, "https://cap-check.example"))
        robots_entry = next(r for r in cap_results if r["path"] == "/robots.txt")
        assert robots_entry["content_preview"] is not None
        assert len(robots_entry["content_preview"]) <= 200
        print("  [+] PASSED")

        # TEST 11: failed scans are never used as a diff baseline (R5-A/B)
        print("\n[TEST 11] Failed-scan baseline...")
        baseline_host = "baseline-check.example"
        save_scan({
            "scan_id": "baseline-ok", "target_url": f"https://{baseline_host}", "hostname": baseline_host,
            "scan_time": "2026-11-01 10:00:00 UTC", "duration_seconds": 1.0, "status": "completed",
            "summary": {"score": 90, "grade": "A", "total_findings": 0, "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
            "findings": [], "headers_analyzed": {}, "ssl_info": None,
        })
        save_scan({
            "scan_id": "baseline-failed", "target_url": f"https://{baseline_host}", "hostname": baseline_host,
            "scan_time": "2026-11-02 10:00:00 UTC", "duration_seconds": 0.5, "status": "failed",
            "error": "Connection error", "summary": None,
            "findings": [], "headers_analyzed": {}, "ssl_info": None,
        })
        prev_scan = get_previous_scan(baseline_host)
        assert prev_scan is not None and prev_scan["scan_id"] == "baseline-ok"
        assert prev_scan["status"] == "completed"
        prev_scan_excluding = get_previous_scan(baseline_host, current_scan_id="baseline-failed")
        assert prev_scan_excluding is not None and prev_scan_excluding["scan_id"] == "baseline-ok"

        failed_only_host = "failed-only.example"
        save_scan({
            "scan_id": "failed-only", "target_url": f"https://{failed_only_host}", "hostname": failed_only_host,
            "scan_time": "2026-11-03 10:00:00 UTC", "duration_seconds": 0.5, "status": "failed",
            "error": "Connection error", "summary": None,
            "findings": [], "headers_analyzed": {}, "ssl_info": None,
        })
        assert get_previous_scan(failed_only_host) is None
        print("  [+] PASSED")

        print("\n==================================================")
        print(" ALL TESTS PASSED")
        print("==================================================")

    except Exception as e:
        print(f"\n[!] TEST FAILED: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)  # R4-4: Exit code 1 on failure
    finally:
        if os.path.exists(temp_db_path):
            try:
                os.remove(temp_db_path)
                print(f"[*] Cleaned up: {temp_db_path}")
            except Exception:
                pass

async def test_takeover_with_mock():
    # Case 1: Dangling CNAME (NXDOMAIN)
    with patch('backend.scanner.subdomain_recon.resolve_status_async', new_callable=AsyncMock) as mock_status:
        mock_status.return_value = ([], "nxdomain")
        sub_info = {"subdomain": "blog.mycorp.com", "ip_addresses": [], "cname": "mycorp.github.io", "alive": False, "wildcard_filtered": False}
        finding = await check_takeover(sub_info, None)
        assert finding is not None
        assert "Dangling CNAME" in finding.title

    # Case 2: CNAME target resolves, HTTP 200, no fingerprint (Negative)
    with patch('backend.scanner.subdomain_recon.resolve_status_async', new_callable=AsyncMock) as mock_status:
        mock_status.return_value = (["1.2.3.4"], "ok")
        sub_info = {"subdomain": "safe.mycorp.com", "ip_addresses": ["5.6.7.8"], "cname": "mycorp.github.io", "alive": True, "wildcard_filtered": False}

        # MagicMock, not AsyncMock: "async with session.get(...)" needs a real
        # context-manager object whose __aenter__/__aexit__ are async.
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.text = AsyncMock(return_value="<html>Welcome</html>")

        mock_get_cm = MagicMock()
        mock_get_cm.__aenter__ = AsyncMock(return_value=mock_resp)
        mock_get_cm.__aexit__ = AsyncMock(return_value=False)

        mock_session = MagicMock()
        mock_session.get.return_value = mock_get_cm

        finding = await check_takeover(sub_info, mock_session)
        assert finding is None

    # Case 4: Matching provider fingerprint over HTTP (Positive)
    with patch('backend.scanner.subdomain_recon.resolve_status_async', new_callable=AsyncMock) as mock_status:
        mock_status.return_value = (["1.2.3.4"], "ok")
        sub_info = {"subdomain": "gone.mycorp.com", "ip_addresses": ["5.6.7.8"], "cname": "gone.github.io", "alive": True, "wildcard_filtered": False}

        mock_resp = MagicMock()
        mock_resp.status = 404
        mock_resp.text = AsyncMock(return_value="<html>There isn't a GitHub Pages site here</html>")

        mock_get_cm = MagicMock()
        mock_get_cm.__aenter__ = AsyncMock(return_value=mock_resp)
        mock_get_cm.__aexit__ = AsyncMock(return_value=False)

        mock_session = MagicMock()
        mock_session.get.return_value = mock_get_cm

        finding = await check_takeover(sub_info, mock_session)
        assert finding is not None
        assert "GitHub Pages" in finding.title

    # Case 3: DNS Error (R4-6)
    with patch('backend.scanner.subdomain_recon.resolve_status_async', new_callable=AsyncMock) as mock_status:
        mock_status.return_value = ([], "error")
        sub_info = {"subdomain": "err.mycorp.com", "ip_addresses": [], "cname": "mycorp.github.io", "alive": False, "wildcard_filtered": False}
        finding = await check_takeover(sub_info, None)
        assert finding is None

if __name__ == "__main__":
    test_all()