"""Documentation contracts for exact connection-pool count value types."""

from __future__ import annotations

from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
POOL_GUIDE_PATH = (
    REPOSITORY_ROOT / "docs" / "research" / "connection-pool-resource-limits.md"
)


def test_connection_pool_guide_documents_exact_builtin_count_values() -> None:
    """Keep operator guidance aligned with the primitive-value integrity boundary."""
    guide = " ".join(POOL_GUIDE_PATH.read_text(encoding="utf-8").split())

    for fragment in (
        "exact built-in `int`",
        "Integer subclasses are rejected",
        "must migrate",
        "approved ASCII decimal string",
    ):
        assert fragment in guide
