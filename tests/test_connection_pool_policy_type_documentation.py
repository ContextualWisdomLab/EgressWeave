"""Documentation contracts for exact connection-pool policy configuration."""

from __future__ import annotations

from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
POOL_GUIDE_PATH = (
    REPOSITORY_ROOT / "docs" / "research" / "connection-pool-resource-limits.md"
)


def _read(path: Path) -> str:
    """Return one repository text file as normalized UTF-8 text."""
    return " ".join(path.read_text(encoding="utf-8").split())


def test_pool_guide_requires_exact_reviewed_policy_type() -> None:
    """Explain why pool-policy subclass polymorphism is not a supported boundary."""
    guide = _read(POOL_GUIDE_PATH)

    for fragment in (
        "exact `EgressConnectionPoolPolicy` type",
        "subclass",
        "trusted policy construction",
        "`connection_pool_policy`",
        "must migrate",
    ):
        assert fragment in guide
