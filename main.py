import os
import re
import uuid
import asyncio
from contextlib import asynccontextmanager
from typing import List, Dict, Optional, Any
from urllib.parse import urlparse

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel

from backend.models import ScanRequest, ScanResult
from backend.scanner.engine import run_scan
from backend.scanner.subdomain_recon import run_subdomain_recon
from backend.scanner.normalize import normalize_domain, validate_domain  # H3
from backend import database as db


@asynccontextmanager
async def lifespan(app: FastAPI):
    db.init_db()
    yield


app = FastAPI(
    title="AegisWeb Advisory Scanner",
    description="All-in-one Web Security Auditing Tool with Subdomain Recon & Metasploit Advisory",
    version="1.2.1",
    lifespan=lifespan,
)

# Secure CORS — local dashboard only
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://127.0.0.1:8000",
        "http://localhost:8000",
        "http://127.0.0.1:3000",
        "http://localhost:3000",
    ],
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# /api/scan
# ---------------------------------------------------------------------------
@app.post("/api/scan", response_model=ScanResult)
async def perform_scan(request: ScanRequest):
    if not request.url or not request.url.strip():
        raise HTTPException(status_code=400, detail="Target URL cannot be empty.")
    result = await run_scan(request)

    res_dict = result.model_dump() if hasattr(result, "model_dump") else result.dict()  # L3

    # Calculate change diff against the last completed scan (failed scans are still saved, but never diffed)
    if result.status != "failed":
        prev_scan = db.get_previous_scan(result.hostname, current_scan_id=result.scan_id)
        if prev_scan:
            result.diff = db.compute_scan_diff(res_dict, prev_scan)
            res_dict["diff"] = result.diff

    db.save_scan(res_dict)
    return result


# ---------------------------------------------------------------------------
# /api/history
# ---------------------------------------------------------------------------
@app.get("/api/history", response_model=List[Dict])
async def get_history():
    return db.list_scans()


@app.get("/api/history/{scan_id}", response_model=ScanResult)
async def get_scan_detail(scan_id: str):
    payload = db.load_scan(scan_id)
    if not payload:
        raise HTTPException(status_code=404, detail="Scan ID not found.")
    return ScanResult(**payload)


# ---------------------------------------------------------------------------
# /api/recon — Subdomain Recon (Scope Gate + Consent required)
# ---------------------------------------------------------------------------
class ReconRequest(BaseModel):
    domain: str
    consent: bool = False
    confirm_domain: Optional[str] = None
    max_concurrent: int = 8


@app.post("/api/recon")
async def start_recon(request: ReconRequest, http_req: Request):
    if not request.domain or not request.domain.strip():
        raise HTTPException(status_code=400, detail="Domain cannot be empty.")

    # Normalize domain using centralized normalizer (H3, A7)
    domain = normalize_domain(request.domain)

    # Validate domain BEFORE logging consent or processing (H8)
    if not validate_domain(domain):
        raise HTTPException(
            status_code=400,
            detail="Invalid domain name format. Must be a valid public FQDN (IP addresses and localhost are not supported)."
        )

    client_ip = http_req.client.host if http_req.client else "unknown"
    user_agent = http_req.headers.get("user-agent", "unknown")

    # Audit log consent decision server-side with normalized domain & user-agent (A6, H4)
    db.log_consent(domain=domain, client_ip=client_ip, consent=request.consent, user_agent=user_agent)

    if not request.consent:
        raise HTTPException(
            status_code=403,
            detail=(
                "Scope consent required. You must confirm that you have explicit "
                "authorisation to test all subdomains of this domain before proceeding."
            ),
        )

    # Require client to send matching confirm_domain (H4)
    confirm = normalize_domain(request.confirm_domain or "")
    if confirm != domain:
        raise HTTPException(
            status_code=403,
            detail="Scope confirmation mismatch. The confirmed domain must match the target domain exactly."
        )

    # Server-side clamp for max_concurrent: 1..20 (B1)
    clamped_concurrent = min(max(1, request.max_concurrent), 20)

    recon_id = str(uuid.uuid4())

    # Check for previous recon of the same domain
    prev_recon = db.get_previous_recon(domain)

    result = await run_subdomain_recon(
        domain=domain,
        max_concurrent=clamped_concurrent,
        timeout=12,
    )
    result["recon_id"] = recon_id
    result["domain"] = domain

    if prev_recon:
        result["diff"] = db.compute_recon_diff(result, prev_recon)

    db.save_recon(recon_id, domain, result)
    return result


@app.get("/api/recon/history")
async def get_recon_history():
    return db.list_recons()


@app.get("/api/recon/{recon_id}")
async def get_recon_detail(recon_id: str):
    payload = db.load_recon(recon_id)
    if not payload:
        raise HTTPException(status_code=404, detail="Recon ID not found.")
    return payload


# ---------------------------------------------------------------------------
# Backend batch scan endpoint (B2, B3, B4, H5, M5)
# ---------------------------------------------------------------------------
class ReconBatchScanRequest(BaseModel):
    subdomains: Optional[List[str]] = None
    scan_all: bool = False
    confirm_scope: bool = False
    max_concurrent: int = 5


@app.post("/api/recon/{recon_id}/scan")
async def run_recon_batch_scan(recon_id: str, batch_req: ReconBatchScanRequest):
    # Require scope confirmation for batch operations (H5)
    if not batch_req.confirm_scope:
        raise HTTPException(
            status_code=403,
            detail="Scope confirmation required. You must confirm scope before executing batch scans."
        )

    recon_payload = db.load_recon(recon_id)
    if not recon_payload:
        raise HTTPException(status_code=404, detail="Recon record not found.")

    all_recon_subs = {s["subdomain"] for s in recon_payload.get("subdomains", [])}
    if batch_req.scan_all:
        targets = [
            s["subdomain"] for s in recon_payload.get("subdomains", [])
            if s.get("alive") and not s.get("wildcard_filtered")
        ]
    else:
        # Validate that each target belongs to this recon
        targets = [s for s in (batch_req.subdomains or []) if s in all_recon_subs]

    # Deduplicate while preserving order (H5)
    targets = list(dict.fromkeys(targets))

    if not targets:
        raise HTTPException(status_code=400, detail="No valid targets found for this recon.")

    # Target cap of 50 to prevent overload (H5)
    MAX_BATCH_TARGETS = 50
    if len(targets) > MAX_BATCH_TARGETS:
        raise HTTPException(
            status_code=400,
            detail=f"Target count {len(targets)} exceeds maximum batch limit of {MAX_BATCH_TARGETS}."
        )

    sem = asyncio.Semaphore(min(max(1, batch_req.max_concurrent), 10))

    async def scan_single(sub: str) -> Dict[str, Any]:
        async with sem:
            # Try HTTPS first, fall back to HTTP if HTTPS fails (B4)
            url_https = f"https://{sub}"
            scan_request = ScanRequest(url=url_https, scan_headers=True, scan_ssl=True, scan_recon=False, timeout=8)
            scan_res = await run_scan(scan_request)

            used_url = url_https
            if scan_res.status == "failed":
                url_http = f"http://{sub}"
                scan_request_http = ScanRequest(url=url_http, scan_headers=True, scan_ssl=False, scan_recon=False, timeout=8)
                scan_res_http = await run_scan(scan_request_http)
                if scan_res_http.status != "failed":
                    scan_res = scan_res_http
                    used_url = url_http

            res_dict = scan_res.model_dump() if hasattr(scan_res, "model_dump") else scan_res.dict()  # L3

            # Compute change diff against the last completed scan in batch path (M5);
            # failed scans are still saved but must not become/produce a baseline.
            if scan_res.status != "failed":
                prev_scan = db.get_previous_scan(scan_res.hostname, current_scan_id=scan_res.scan_id)
                if prev_scan:
                    scan_res.diff = db.compute_scan_diff(res_dict, prev_scan)
                    res_dict["diff"] = scan_res.diff

            db.save_scan(res_dict)

            # Safe extraction of score/grade even if summary is None (M5)
            score = scan_res.summary.score if scan_res.summary else None
            grade = scan_res.summary.grade if scan_res.summary else None

            return {
                "subdomain": sub,
                "url": used_url,
                "scan_id": scan_res.scan_id,
                "status": scan_res.status,
                "score": score,
                "grade": grade,
                "error": scan_res.error if scan_res.status == "failed" else None,
            }

    results = await asyncio.gather(*[scan_single(t) for t in targets])
    completed_count = sum(1 for r in results if r["status"] == "completed")
    failed_count = sum(1 for r in results if r["status"] == "failed")

    return {
        "recon_id": recon_id,
        "total_requested": len(targets),
        "completed": completed_count,
        "failed": failed_count,
        "results": results,
    }


# ---------------------------------------------------------------------------
# Health + static frontend
# ---------------------------------------------------------------------------
@app.get("/api/health")
async def health_check():
    return {"status": "healthy", "service": "AegisWeb Advisory Scanner", "version": "1.2.1"}


frontend_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "frontend")
if os.path.exists(frontend_dir):
    app.mount("/static", StaticFiles(directory=frontend_dir), name="static")

    @app.get("/")
    async def serve_index():
        return FileResponse(os.path.join(frontend_dir, "index.html"))