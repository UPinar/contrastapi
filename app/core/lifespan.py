"""FastAPI lifespan: DB init, IP intel warm, periodic maintenance, shutdown cleanup.

Built as a factory because `_mcp_session_mgr` is set up after `app = FastAPI()`
in main.py — passing a getter lets us look it up lazily at startup time.
"""

import logging
from collections.abc import Callable
from contextlib import asynccontextmanager
from typing import Any

from db import init_all_dbs

logger = logging.getLogger("contrastapi")


def make_lifespan(get_mcp_session_mgr: Callable[[], Any]):
    """Build a lifespan callable bound to a deferred MCP session-manager getter."""

    @asynccontextmanager
    async def lifespan(app):
        import asyncio

        init_all_dbs()
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
        # Catch BaseException so a CancelledError mid-shutdown does not leak the
        # remaining clients' connections (CancelledError is not Exception in 3.8+).
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
            except BaseException:
                pass
        # Close thread-local DB connections
        from db import close_thread_connections

        close_thread_connections()

    return lifespan
