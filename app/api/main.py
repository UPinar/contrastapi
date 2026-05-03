"""`/v1` aggregator. One place to add a new package router; one place to bump
the version prefix when /v2 lands.

Aggregator INSIDE: cve, domain, codesec, ioc, atlas (/atlas), d3fend (/d3fend).
Aggregator OUTSIDE (separate `app.include_router` in main.py):
  - webhooks_router (`/webhooks/lemonsqueezy`, NOT /v1)
  - crypto_billing_router (literal `/v1/billing/crypto/*` paths)
"""

from api.meta import router as meta_router
from atlas.routes import router as atlas_router
from codesec.routes import router as codesec_router
from cve.routes import router as cve_router
from d3fend.routes import router as d3fend_router
from domain.routes import router as domain_router
from fastapi import APIRouter
from ioc.routes import router as ioc_router

api_router = APIRouter(prefix="/v1")

# Order preserved from pre-Faz-6 main.py (1249-1266) — OpenAPI tag insertion-order.
api_router.include_router(domain_router)
api_router.include_router(cve_router)
api_router.include_router(codesec_router)
api_router.include_router(ioc_router)
api_router.include_router(atlas_router)
api_router.include_router(d3fend_router)
api_router.include_router(meta_router)
