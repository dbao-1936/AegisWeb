"""
Persistence Layer: SQLite-backed scan history & change tracking over time
Replaces in-memory storage so history survives server restarts.
"""
import sqlite3
import json
import os
import logging
from typing import List, Optional, Dict, Any
from datetime import datetime, timezone
from contextlib import contextmanager

logger = logging.getLogger("aegisweb.database")

def get_db_path() -> str:
    return os.environ.get(
        "AEGISWEB_DB",
        os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "aegisweb.db")
    )


@contextmanager
def get_db():
    """Context manager yielding a connection that commits and closes reliably."""
    db_path = get_db_path()
    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db():
    """Create directory and tables if they don't exist."""
    db_path = get_db_path()
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    with get_db() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS scans (
                scan_id     TEXT PRIMARY KEY,
                target_url  TEXT NOT NULL,
                hostname    TEXT NOT NULL,
                scan_time   TEXT NOT NULL,
                duration    REAL,
                score       INTEGER,
                grade       TEXT,
                status      TEXT,
                payload     TEXT NOT NULL,
                created_at  TEXT DEFAULT (strftime('%Y-%m-%d %H:%M:%f', 'now'))
            );

            CREATE TABLE IF NOT EXISTS subdomain_recons (
                recon_id    TEXT PRIMARY KEY,
                domain      TEXT NOT NULL,
                scan_time   TEXT NOT NULL,
                payload     TEXT NOT NULL,
                created_at  TEXT DEFAULT (strftime('%Y-%m-%d %H:%M:%f', 'now'))
            );

            CREATE TABLE IF NOT EXISTS consent_logs (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                domain      TEXT NOT NULL,
                client_ip   TEXT,
                user_agent  TEXT,
                consent     INTEGER NOT NULL,
                timestamp   TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_scans_hostname ON scans(hostname);
            CREATE INDEX IF NOT EXISTS idx_scans_created  ON scans(hostname, created_at);
            CREATE INDEX IF NOT EXISTS idx_recon_domain   ON subdomain_recons(domain);
            CREATE INDEX IF NOT EXISTS idx_recon_created  ON subdomain_recons(domain, created_at);
        """)
        # Ensure user_agent column exists for older schema
        try:
            conn.execute("ALTER TABLE consent_logs ADD COLUMN user_agent TEXT")
        except Exception:
            pass


def log_consent(domain: str, client_ip: str, consent: bool, user_agent: str = "unknown"):
    """Store an audit record of scope consent (H4)."""
    with get_db() as conn:
        conn.execute(
            """
            INSERT INTO consent_logs (domain, client_ip, user_agent, consent, timestamp)
            VALUES (?, ?, ?, ?, strftime('%Y-%m-%d %H:%M:%f', 'now'))
            """,
            (domain, client_ip, user_agent, 1 if consent else 0),
        )


def save_scan(result: Dict[str, Any]):
    """Persist a scan result to SQLite."""
    with get_db() as conn:
        conn.execute(
            """
            INSERT OR REPLACE INTO scans
                (scan_id, target_url, hostname, scan_time, duration, score, grade, status, payload, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, strftime('%Y-%m-%d %H:%M:%f', 'now'))
            """,
            (
                result["scan_id"],
                result["target_url"],
                result["hostname"],
                result["scan_time"],
                result.get("duration_seconds"),
                (result.get("summary") or {}).get("score"),
                (result.get("summary") or {}).get("grade"),
                result.get("status"),
                json.dumps(result),
            ),
        )


def load_scan(scan_id: str) -> Optional[Dict[str, Any]]:
    with get_db() as conn:
        row = conn.execute("SELECT payload FROM scans WHERE scan_id=?", (scan_id,)).fetchone()
    return json.loads(row["payload"]) if row else None


def list_scans(limit: int = 50) -> List[Dict[str, Any]]:
    with get_db() as conn:
        rows = conn.execute(
            """
            SELECT scan_id, target_url, hostname, scan_time, score, grade, status, payload
            FROM scans ORDER BY created_at DESC, rowid DESC LIMIT ?
            """,
            (limit,),
        ).fetchall()

    results = []
    for row in rows:
        try:
            payload = json.loads(row["payload"])
            results.append({
                "scan_id": row["scan_id"],
                "target_url": row["target_url"],
                "hostname": row["hostname"],
                "scan_time": row["scan_time"],
                "score": row["score"],
                "grade": row["grade"],
                "total_findings": (payload.get("summary") or {}).get("total_findings", 0),
                "critical": (payload.get("summary") or {}).get("critical", 0),
                "high": (payload.get("summary") or {}).get("high", 0),
                "msf_count": len(payload.get("metasploit_suggestions", [])),
                "status": row["status"],
            })
        except Exception as e:
            logger.exception("Error parsing scan payload for row %s: %s", row["scan_id"], e)
    return results


def save_recon(recon_id: str, domain: str, payload: Dict[str, Any]):
    """Persist a subdomain recon result (A1: ensure scan_time is in payload)."""
    scan_time = payload.get("scan_time") or datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    payload["scan_time"] = scan_time
    with get_db() as conn:
        conn.execute(
            """
            INSERT OR REPLACE INTO subdomain_recons (recon_id, domain, scan_time, payload, created_at)
            VALUES (?, ?, ?, ?, strftime('%Y-%m-%d %H:%M:%f', 'now'))
            """,
            (
                recon_id,
                domain,
                scan_time,
                json.dumps(payload),
            ),
        )


def load_recon(recon_id: str) -> Optional[Dict[str, Any]]:
    with get_db() as conn:
        row = conn.execute(
            "SELECT payload FROM subdomain_recons WHERE recon_id=?", (recon_id,)
        ).fetchone()
    return json.loads(row["payload"]) if row else None


def list_recons(domain: Optional[str] = None, limit: int = 20) -> List[Dict[str, Any]]:
    with get_db() as conn:
        if domain:
            rows = conn.execute(
                "SELECT recon_id, domain, scan_time, payload FROM subdomain_recons WHERE domain=? ORDER BY created_at DESC, rowid DESC LIMIT ?",
                (domain, limit),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT recon_id, domain, scan_time, payload FROM subdomain_recons ORDER BY created_at DESC, rowid DESC LIMIT ?",
                (limit,),
            ).fetchall()

    results = []
    for row in rows:
        try:
            payload = json.loads(row["payload"])
            results.append({
                "recon_id": row["recon_id"],
                "domain": row["domain"],
                "scan_time": row["scan_time"],
                "total_discovered": payload.get("total_discovered", 0),
                "total_alive": payload.get("total_alive", 0),
                "takeover_count": len(payload.get("takeover_findings", [])),
                "dns_issue_count": len(payload.get("dns_findings", [])),
            })
        except Exception as e:
            logger.exception("Error parsing recon payload for row %s: %s", row["recon_id"], e)
    return results


# ---------------------------------------------------------------------------
# CHANGE TRACKING / COMPARISON ENGINE
# ---------------------------------------------------------------------------

def get_previous_scan(hostname: str, current_scan_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Retrieve the most recent prior scan for the same host."""
    with get_db() as conn:
        if current_scan_id:
            row = conn.execute(
                "SELECT payload FROM scans WHERE hostname=? AND scan_id != ? AND status = 'completed' ORDER BY created_at DESC, rowid DESC LIMIT 1",
                (hostname, current_scan_id),
            ).fetchone()
        else:
            row = conn.execute(
                "SELECT payload FROM scans WHERE hostname=? AND status = 'completed' ORDER BY created_at DESC, rowid DESC LIMIT 1",
                (hostname,),
            ).fetchone()
    return json.loads(row["payload"]) if row else None


def compute_scan_diff(current: Dict[str, Any], previous: Dict[str, Any]) -> Dict[str, Any]:
    """Calculate delta between current scan and previous scan."""
    curr_score = (current.get("summary") or {}).get("score", 0)
    prev_score = (previous.get("summary") or {}).get("score", 0)

    curr_findings = {f["id"]: f for f in current.get("findings", [])}
    prev_findings = {f["id"]: f for f in previous.get("findings", [])}

    new_finding_ids = set(curr_findings.keys()) - set(prev_findings.keys())
    resolved_finding_ids = set(prev_findings.keys()) - set(curr_findings.keys())

    curr_headers = current.get("headers_analyzed", {})
    prev_headers = previous.get("headers_analyzed", {})

    headers_added = []
    headers_removed = []
    for h, info in curr_headers.items():
        if isinstance(info, dict) and info.get("present") and not prev_headers.get(h, {}).get("present"):
            headers_added.append(h)
    for h, info in prev_headers.items():
        if isinstance(info, dict) and info.get("present") and not curr_headers.get(h, {}).get("present"):
            headers_removed.append(h)

    curr_ssl = current.get("ssl_info") or {}
    prev_ssl = previous.get("ssl_info") or {}
    ssl_days_curr = curr_ssl.get("expires_in_days")
    ssl_days_prev = prev_ssl.get("expires_in_days")

    return {
        "has_previous": True,
        "previous_scan_id": previous.get("scan_id"),
        "previous_scan_time": previous.get("scan_time"),
        "score_delta": curr_score - prev_score,
        "previous_score": prev_score,
        "new_findings": [curr_findings[fid] for fid in new_finding_ids],
        "resolved_findings": [prev_findings[fid] for fid in resolved_finding_ids],
        "headers_added": headers_added,
        "headers_removed": headers_removed,
        "ssl_days_left": ssl_days_curr,
        "ssl_days_prev": ssl_days_prev,
    }


def get_previous_recon(domain: str, current_recon_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Retrieve the most recent prior subdomain recon for the same domain."""
    with get_db() as conn:
        if current_recon_id:
            row = conn.execute(
                "SELECT payload FROM subdomain_recons WHERE domain=? AND recon_id != ? ORDER BY created_at DESC, rowid DESC LIMIT 1",
                (domain, current_recon_id),
            ).fetchone()
        else:
            row = conn.execute(
                "SELECT payload FROM subdomain_recons WHERE domain=? ORDER BY created_at DESC, rowid DESC LIMIT 1",
                (domain,),
            ).fetchone()
    return json.loads(row["payload"]) if row else None


def compute_recon_diff(current: Dict[str, Any], previous: Dict[str, Any]) -> Dict[str, Any]:
    """Calculate delta between current recon and previous recon."""
    curr_subs = {s["subdomain"] for s in current.get("subdomains", [])}
    prev_subs = {s["subdomain"] for s in previous.get("subdomains", [])}

    new_subdomains = sorted(list(curr_subs - prev_subs))
    removed_subdomains = sorted(list(prev_subs - curr_subs))

    curr_takeovers = {f["id"]: f for f in current.get("takeover_findings", [])}
    prev_takeovers = {f["id"]: f for f in previous.get("takeover_findings", [])}

    new_takeovers = [curr_takeovers[k] for k in set(curr_takeovers.keys()) - set(prev_takeovers.keys())]

    return {
        "has_previous": True,
        "previous_recon_id": previous.get("recon_id"),
        "previous_scan_time": previous.get("scan_time"),
        "new_subdomains": new_subdomains,
        "removed_subdomains": removed_subdomains,
        "new_takeovers": new_takeovers,
        "previous_total": len(prev_subs),
    }
