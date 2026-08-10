"""Documentation contracts for exact connection-pool policy configuration."""

from __future__ import annotations

from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
POOL_GUIDE_PATH = (
    REPOSITORY_ROOT / "docs" / "research" / "connection-pool-resource-limits.md"
)
CHANGELOG_PATH = REPOSITORY_ROOT / "CHANGELOG.md"


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
    ):
        assert fragment in guide


def test_changelog_records_connection_pool_policy_type_hardening() -> None:
    """Expose the pre-1.0 pool-policy integrity tightening to integrators."""
    changelog = _read(CHANGELOG_PATH)

    for fragment in (
        "connection pool policy",
        "exact `EgressConnectionPoolPolicy`",
        "subclass",
    ):
        assert fragment in changelog
