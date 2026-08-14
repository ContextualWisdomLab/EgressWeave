"""Documentation contracts for exact request-timeout policy configuration."""

from __future__ import annotations

from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
TIMEOUT_GUIDE_PATH = REPOSITORY_ROOT / "docs" / "research" / "request-timeout-boundaries.md"


def _read(path: Path) -> str:
    """Return one repository text file as normalized UTF-8 prose."""
    return " ".join(path.read_text(encoding="utf-8").split())


def test_timeout_guide_requires_exact_reviewed_policy_type() -> None:
    """Explain why timeout-policy subclass polymorphism is not supported."""
    guide = _read(TIMEOUT_GUIDE_PATH)

    for fragment in (
        "exact `EgressTimeoutPolicy` type",
        "subclass",
        "trusted policy-construction boundary",
        "`as_httpcore_timeout()`",
        "must migrate",
    ):
        assert fragment in guide
