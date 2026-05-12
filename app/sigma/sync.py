"""Sigma corpus sync — invoke shell sparse-clone, then reload in-memory index."""

import logging
import subprocess
from pathlib import Path

from sigma import get_sigma_index

logger = logging.getLogger("contrastapi")

SCRIPT_PATH = Path(__file__).resolve().parent.parent.parent / "scripts" / "refresh_sigma.sh"


def refresh_sigma_corpus(sigma_path: Path, *, timeout: int = 300) -> int:
    """Sparse-clone or update SigmaHQ rules into ``sigma_path``, then rebuild the
    in-memory index. Returns the number of rules indexed.

    Caller (cron / admin endpoint) supplies the target directory; the shell
    script handles git plumbing. The index is rebuilt against the now-fresh
    directory contents.
    """
    sigma_path = Path(sigma_path)
    sigma_path.mkdir(parents=True, exist_ok=True)
    try:
        result = subprocess.run(
            ["bash", str(SCRIPT_PATH), str(sigma_path)],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        logger.warning("Sigma sync timed out after %ds — keeping existing index", timeout)
        return len(get_sigma_index().rules)
    except FileNotFoundError:
        logger.warning("Sigma sync script not found at %s — keeping existing index", SCRIPT_PATH)
        return len(get_sigma_index().rules)

    if result.returncode != 0:
        logger.warning("Sigma sync exited %d: %s", result.returncode, result.stderr.strip()[:500])
        return len(get_sigma_index().rules)

    # Non-atomic reload: clear-then-reload window (~3s for 3k rules) leaves the
    # index partially populated. Acceptable for B1 because production uses
    # cron + rolling restart (this function isn't called at runtime); when an
    # admin endpoint or HTTP-triggered sync is added, swap to atomic replace:
    #     new_idx = SigmaRuleIndex(); new_idx.load_from_directory(sigma_path)
    #     sigma._index = new_idx  # GIL-atomic pointer swap
    idx = get_sigma_index()
    idx.rules.clear()
    idx.technique_index.clear()
    idx.cve_index.clear()
    idx.product_index.clear()
    idx.category_index.clear()
    count = idx.load_from_directory(sigma_path)
    logger.info("Sigma sync complete: %d rules indexed from %s", count, sigma_path)
    return count


def load_sigma_corpus(sigma_path: Path) -> int:
    """Boot-time load: index existing on-disk rules without git pull.
    Returns the number of rules indexed (0 if path missing)."""
    sigma_path = Path(sigma_path)
    if not sigma_path.is_dir():
        logger.warning("Sigma corpus path missing: %s — index empty", sigma_path)
        return 0
    idx = get_sigma_index()
    count = idx.load_from_directory(sigma_path)
    logger.info("Sigma boot load: %d rules indexed from %s", count, sigma_path)
    return count
