"""Documentation contracts for synchronous finite connection deadlines."""

from __future__ import annotations

from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
RESEARCH_PATH = REPOSITORY_ROOT / "docs" / "research" / "staggered-connection-attempts.md"
CHANGELOG_PATH = REPOSITORY_ROOT / "CHANGELOG.md"


def _normalized_text(path: Path) -> str:
    """Return repository documentation with whitespace normalized for assertions."""
    return " ".join(path.read_text(encoding="utf-8").split())


def test_research_documents_zero_budget_sync_connection_refusal() -> None:
    """Document that an exhausted sync budget creates no TCP attempt."""
    research = _normalized_text(RESEARCH_PATH)

    assert "synchronous transport" in research
    assert "zero remaining connection budget" in research
    assert "does not start a TCP attempt" in research


def test_changelog_records_zero_budget_sync_connection_refusal() -> None:
    """Expose the synchronous resource-boundary tightening in release history."""
    changelog = _normalized_text(CHANGELOG_PATH)

    assert "synchronous pinned transport" in changelog
    assert "zero remaining connection budget" in changelog
    assert "TCP attempt" in changelog
