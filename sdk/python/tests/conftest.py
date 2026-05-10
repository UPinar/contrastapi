"""Pytest config for SDK tests.

`pytest_asyncio.mode = "auto"` lets us write `async def test_*` without an
explicit decorator. We also add the SDK's parent directory to `sys.path` so
tests run directly from the repo without needing `pip install -e .`.
"""

from __future__ import annotations

import sys
from pathlib import Path

_SDK_ROOT = Path(__file__).resolve().parent.parent
if str(_SDK_ROOT) not in sys.path:
    sys.path.insert(0, str(_SDK_ROOT))
