"""FastAPI lifespan: DB init, IP intel warm, periodic maintenance, shutdown cleanup.

Built as a factory because `_mcp_session_mgr` is set up after `app = FastAPI()`
in main.py — passing a getter lets us look it up lazily at startup time.
"""

import logging
from collections.abc import Callable
from contextlib import asynccontextmanager
from typing import Any

from config import BASE_DIR, settings
from core import mcp_proxy
from db import init_all_dbs
from sigma.sync import load_sigma_corpus

logger = logging.getLogger("contrastapi")


def _warn_if_paths_under_base_dir() -> None:
    """If any operational path falls back to BASE_DIR, the operator forgot to
    set the corresponding env var — log a warning so the slip is visible at
    startup instead of being noticed days later when the data is in the wrong
    place. Silent in dev (where BASE_DIR-relative paths are intentional)."""
    fallbacks = []
    for env_name, path in (
        ("CONTRASTAPI_DB", settings.api_db),
        ("CONTRASTAPI_CVE_DB", settings.cve_db),
        ("CONTRASTAPI_CACHE_DB", settings.cache_db),
        ("CONTRASTAPI_SIGMA_PATH", settings.sigma_path),
        ("MCP_TOOL_LOG_PATH", settings.mcp_tool_log_path),
        ("GLAMA_MANIFEST_PATH", settings.glama_manifest_path),
    ):
        try:
            path.resolve().relative_to(BASE_DIR.resolve())
        except ValueError:
            continue  # path is outside BASE_DIR — env var was honored
        fallbacks.append(env_name)
    if fallbacks:
        logger.warning(
            "Operational paths fell back to BASE_DIR — env vars unset: %s",
            ", ".join(fallbacks),
        )


def make_lifespan(get_mcp_session_mgr: Callable[[], Any]):
    """Build a lifespan callable bound to a deferred MCP session-manager getter."""

    @asynccontextmanager
    async def lifespan(app):
        import asyncio

        init_all_dbs()
        _warn_if_paths_under_base_dir()
        load_sigma_corpus(settings.sigma_path)
        await mcp_proxy.build_and_set_tools_list_cache()
        logger.info("ContrastAPI started — databases initialized")

        # Non-blocking warm: run cache refresh in background so startup is not
        # held hostage by slow/poisoned upstream DNS or connectivity.
        async def _warm_ip_intel():
            from domain.ip_intel import _refresh_cloud_cache, _refresh_tor_cache

            for name, fn in (("cloud", _refresh_cloud_cache), ("tor", _refresh_tor_cache)):
                try:
                    await asyncio.wait_for(fn(), timeout=20)
                except asyncio.CancelledError:
                    raise
                except asyncio.TimeoutError:
                    logger.warning("IP intel %s warm timed out (20s)", name)
                except Exception as e:
                    logger.warning("IP intel %s warm failed: %s", name, type(e).__name__)
            logger.info("IP intel caches warm attempt complete")

        warm_task = asyncio.create_task(_warm_ip_intel())

        # Periodic DB maintenance (every hour). Each step is independently guarded
        # so one failure never kills the loop.
        async def _periodic_maintenance():
            while True:
                try:
                    await asyncio.sleep(3600)
                except asyncio.CancelledError:
                    raise
                try:
                    from db import maintenance
                    from ratelimit import cleanup_expired

                    stats = maintenance()
                    expired = cleanup_expired()
                    logger.info("DB maintenance: %s, rate_limits cleaned: %d", stats, expired)
                except Exception as e:
                    logger.warning("DB maintenance failed: %s", e)
                try:
                    from domain.ip_intel import _refresh_cloud_cache, _refresh_tor_cache

                    await asyncio.wait_for(_refresh_cloud_cache(), timeout=60)
                    await asyncio.wait_for(_refresh_tor_cache(), timeout=60)
                except asyncio.TimeoutError:
                    logger.warning("IP intel periodic refresh timed out (60s)")
                except Exception as e:
                    logger.warning("IP intel refresh failed: %s", type(e).__name__)

        task = asyncio.create_task(_periodic_maintenance())

        # MCP session manager needs a running task group (skip if mcp not installed)
        mcp_session_mgr = get_mcp_session_mgr()
        if mcp_session_mgr is not None:
            async with mcp_session_mgr.run():
                logger.info("MCP Streamable HTTP endpoint ready at /mcp")
                yield
        else:
            yield

        # Stop maintenance + warm tasks
        task.cancel()
        warm_task.cancel()
        # Close HTTP clients
        from atlas.sync import _client as atlas_client
        from cve.routes import _exploit_client
        from cve.sync import _client as sync_client
        from d3fend.sync import _client as d3fend_client
        from domain.archive import _client as wayback_client
        from domain.ip_intel import _intel_client
        from domain.recon import _http as recon_client
        from domain.recon import _ssrf_http
        from domain.reputation import _client as rep_client
        from domain.routes import _ripe_client
        from domain.threat import _client as threat_client
        from domain.username import _client as username_client
        from ioc.lookup import _client as ioc_client
        from ioc.password import _client as password_client
        from ioc.routes import _phish_client

        # AsyncClient — must use aclose() to release the underlying HTTP/2 transport.
        # Include CancelledError so a cancel mid-shutdown does not leak the remaining
        # clients' connections (CancelledError is not a subclass of Exception in 3.8+).
        # KeyboardInterrupt / SystemExit are intentionally NOT caught so they still
        # propagate out of the lifespan exit.
        for ac in (
            _exploit_client,
            _phish_client,
            ioc_client,
            password_client,
            recon_client,
            _ssrf_http,
            threat_client,
            rep_client,
            sync_client,
            _ripe_client,
            atlas_client,
            d3fend_client,
            wayback_client,
            username_client,
            _intel_client,
        ):
            try:
                await ac.aclose()
            except (Exception, asyncio.CancelledError):
                # Best-effort cleanup; one client failing to close must not strand the others.
                pass
        # Close thread-local DB connections
        from db import close_thread_connections

        close_thread_connections()
        # Shut down the dedicated DNS executor used by the SSRF backend.
        from domain.recon import _DNS_EXECUTOR

        _DNS_EXECUTOR.shutdown(wait=False)

    return lifespan
