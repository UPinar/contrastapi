"""Sigma detection rule corpus module — lookup + index."""

from sigma.index import SigmaRuleIndex

_index: SigmaRuleIndex | None = None


def get_sigma_index() -> SigmaRuleIndex:
    """Return process-wide SigmaRuleIndex singleton (lazy init)."""
    global _index
    if _index is None:
        _index = SigmaRuleIndex()
    return _index
