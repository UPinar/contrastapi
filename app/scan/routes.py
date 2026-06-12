"""Website-scanner API route — GET /v1/scan/{domain} (Faz-2: REST + MCP wiring).

Pattern B (v1.32.4 convention, mirror of audit_domain): the REST handler below
and the MCP `contrast_scan` wrapper (mcp_server.py) both call the shared
`_contrast_scan_impl()`. Exactly one gate charges per call — the REST gate via
`require_auth("/v1/scan", cost=COST_SCAN)` for HTTP, the MCP gate via
`_TOOL_COST["contrast_scan"]` for tools/call — and the impl itself never
charges.

Route-ordering note: codesec's `/scan/headers/{domain}` (3 path segments) and
this module's `/scan/{domain}` (2 segments) can never match the same request
because path params do not span slashes. `app/api/main.py` still includes
scan_router AFTER codesec_router so the static-prefix route registers first —
documented defense-in-depth in case either path shape ever changes.
"""

from typing import Annotated

from auth import AuthCtx, require_auth
from config import COST_SCAN
from fastapi import APIRouter, Depends, HTTPException, Path

# The engine entrypoint (scan/engine.py) and the MCP tool are BOTH named
# `contrast_scan` — alias the engine import so the names cannot collide and
# tests get a patchable seam (`scan.routes._run_scan_engine`).
from scan.engine import contrast_scan as _run_scan_engine
from scan.schemas import ScanResponse
from schemas import PivotHint

scan_router = APIRouter(tags=["Website Scanner"])


@scan_router.get(
    "/scan/{domain}",
    operation_id="contrast_scan",
    response_model=ScanResponse,
    response_model_exclude_none=True,
)
async def contrast_scan_endpoint(
    domain: Annotated[
        str,
        Path(
            description=(
                "Registrable domain, e.g. 'example.com'. Scheme/path/port are stripped. "
                "Bare IPs and private-resolving domains are rejected (SSRF defense)."
            ),
        ),
    ],
    auth: Annotated[AuthCtx, Depends(require_auth("/v1/scan", cost=COST_SCAN))],
):
    """Active website security scan — C scanner engine (11 modules) + severity-ranked findings.

    Runs HTTP security headers, SSL/TLS, DNS, redirect-chain, information
    disclosure, cookie-flags, DNSSEC, HTTP-methods, CORS, HTML, and deep-CSP
    checks against the live site and returns a letter grade plus enriched,
    severity-sorted findings. Performs active outbound requests — a per-target
    eTLD+1 throttle (60 req/min) applies on top of the caller's rate limit.
    """
    return await _contrast_scan_impl(domain, tier=auth.tier, client_ip=auth.client_ip)


async def _contrast_scan_impl(
    domain: str,
    *,
    tier: str = "pro",
    client_ip: str = "",
) -> dict:
    """Pattern B shared implementation — called by both the REST handler above
    and the MCP `contrast_scan` wrapper (mcp_server.py). Centralizing here means
    one rate-limit consume per call: REST gate when invoked via HTTP, MCP gate
    via `_TOOL_COST["contrast_scan"]` when invoked via tools/call. Raises
    `HTTPException` on validation/throttle/scanner failure (REST contract); the
    MCP wrapper catches and converts to `AppException` for the FastMCP error
    envelope.

    `tier` / `client_ip` are accepted for Pattern B signature parity (impl
    contract tests + future tier-gated scan depth); the engine itself is
    tier-agnostic today.
    """
    from scan.validation import clean_domain
    from target_throttle import consume_target_throttle

    try:
        cleaned = clean_domain(domain)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=f"Invalid domain: {exc}") from exc

    # Per-target eTLD+1 throttle (60 req/min) — unlike audit_domain (passive
    # recon, no throttle), the scanner actively probes the target, so a single
    # Pro key must not be able to weaponise the API against one site. Same
    # block as robots_txt / seo_audit / brand_assets (domain/routes.py:1352).
    allowed, retry_after = consume_target_throttle(cleaned)
    if not allowed:
        raise HTTPException(
            status_code=429,
            detail=f"Target throttle: {cleaned} exceeded the per-domain limit. retry_after={retry_after}s",
            headers={"Retry-After": str(retry_after)},
        )

    result = await _run_scan_engine(cleaned)
    # The active scan deliberately drops the old web UI's async "recon" tab
    # (WHOIS / infra / subdomains / fingerprint). Surface cascade hints so an
    # agent can pull that ground from the dedicated tools instead.
    result["next_calls"] = [h.model_dump() for h in _scan_pivot_hints(cleaned)]
    return result


def _scan_pivot_hints(domain: str) -> list[PivotHint]:
    """Replace the dropped passive-recon section with hints to the dedicated MCP
    tools. A successful scan implies the domain resolved, so these are emitted
    unconditionally. scan_headers / ssl_check are intentionally absent — this
    scan already ran the headers + ssl modules, so re-calling them duplicates work.
    """
    return [
        PivotHint(
            tool="subdomain_enum",
            input=domain,
            reason="Map attack surface — enumerate subdomains via crt.sh CT logs + DNS wordlist (passive).",
        ),
        PivotHint(
            tool="tech_fingerprint",
            input=domain,
            reason="Detect tech stack (CMS, framework, CDN, web server) — then pivot to tech_stack_cve_audit.",
        ),
        PivotHint(
            tool="audit_domain",
            input=domain,
            reason="Passive recon bundle: WHOIS, DNS, SSL chain, threat-intel — the recon the active scan omits.",
        ),
    ]
