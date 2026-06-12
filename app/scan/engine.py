"""Website-scanner engine orchestration (Faz-1: engine only, no REST/MCP wiring).

Runs the compiled C scanner binary (``scanner/contrastscan``) as a subprocess
and enriches the raw JSON result with vulnerability findings. REST/MCP
exposure is a deliberately deferred later phase — nothing here is mounted on
the app.
"""

import json
import logging
import subprocess
import threading

from config import SCAN_CONCURRENCY, SCAN_TIMEOUT, SCANNER_PATH
from fastapi import HTTPException
from fastapi.concurrency import run_in_threadpool
from scan.findings import enrich_with_findings
from scan.validation import clean_domain, get_resolved_ip_with_bypass, is_private_ip, validate_domain

logger = logging.getLogger("contrastapi")

# Bounds simultaneous scanner subprocesses; the short acquire timeout converts
# a saturated queue into a fast 503 instead of an unbounded pile-up.
_scan_semaphore = threading.Semaphore(SCAN_CONCURRENCY)
_SEMAPHORE_ACQUIRE_TIMEOUT = 10  # seconds


def run_scan(domain: str, resolved_ip: str | None = None) -> dict:
    """Run the contrastscan binary and parse its JSON stdout.

    ``resolved_ip`` pins DNS inside the C binary (SSRF defense). Failure
    mapping: queue full -> 503, binary missing -> 500, subprocess timeout ->
    504, non-zero exit or unparseable JSON -> 502.
    """
    acquired = _scan_semaphore.acquire(timeout=_SEMAPHORE_ACQUIRE_TIMEOUT)
    if not acquired:
        raise HTTPException(status_code=503, detail="Server busy. Try again in a few seconds.")
    try:
        cmd = [str(SCANNER_PATH), domain]
        if resolved_ip:
            cmd.append(resolved_ip)
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=SCAN_TIMEOUT)
    except subprocess.TimeoutExpired as exc:
        logger.warning("Scan timeout: %s", domain)
        raise HTTPException(status_code=504, detail="Scan timed out") from exc
    except FileNotFoundError as exc:
        logger.error("Scanner binary not found: %s", SCANNER_PATH)
        raise HTTPException(status_code=500, detail="Scanner not available") from exc
    finally:
        _scan_semaphore.release()

    if result.returncode != 0:
        logger.warning("Scan failed: %s (exit %d)", domain, result.returncode)
        raise HTTPException(status_code=502, detail="Scan failed")

    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        logger.error("Invalid scanner JSON for %s", domain)
        raise HTTPException(status_code=502, detail="Scan failed") from exc


async def contrast_scan(domain: str, *, resolved_ip: str | None = None) -> dict:
    """Public engine entry: validate -> self-domain bypass -> scan -> enrich.

    When ``resolved_ip`` is not supplied it is derived via ``validate_domain``
    (DNS + SSRF checks). A caller-supplied ``resolved_ip`` is still rejected
    when private — defense in depth. Validation failures map to HTTP 400.
    """
    try:
        cleaned = clean_domain(domain)
        if resolved_ip is None:
            # validate_domain does blocking DNS (getaddrinfo); run_scan blocks on
            # a subprocess for up to SCAN_TIMEOUT. Both are off-loaded to a thread
            # so a single scan cannot stall the uvicorn worker's event loop.
            resolved_ip = await run_in_threadpool(validate_domain, cleaned)
        elif is_private_ip(resolved_ip):
            raise ValueError("Resolved IP is private")
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=f"Invalid domain: {exc}") from exc

    resolved_ip = get_resolved_ip_with_bypass(cleaned, resolved_ip)
    result = await run_in_threadpool(run_scan, cleaned, resolved_ip)
    result["resolved_ip"] = resolved_ip
    return enrich_with_findings(result)
