"""Documentation contracts for exact connection-pool count value types."""

from __future__ import annotations

from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
POOL_GUIDE_PATH = (
    REPOSITORY_ROOT / "docs" / "research" / "connection-pool-resource-limits.md"
)
CHANGELOG_PATH = REPOSITORY_ROOT / "CHANGELOG.md"


def test_connection_pool_guide_documents_exact_builtin_count_values() -> None:
    """Keep operator guidance aligned with the primitive-value integrity boundary."""
    guide = POOL_GUIDE_PATH.read_text(encoding="utf-8")

    assert "Count fields accept only exact built-in integers" in guide
    assert "integer subclasses are rejected" in guide
    assert "does not make EgressWeave a Python sandbox" in guide


def test_changelog_records_connection_count_value_sealing() -> None:
    """Record the pre-1.0 primitive-value tightening in release history."""
    changelog = CHANGELOG_PATH.read_text(encoding="utf-8")

    assert "Reject non-exact integer subclasses in connection-pool count fields" in changelog
