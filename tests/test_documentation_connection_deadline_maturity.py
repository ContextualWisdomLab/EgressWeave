"""Contracts preventing target connection-deadline behavior from being called shipped."""

from __future__ import annotations

from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
TRD_PATH = REPOSITORY_ROOT / "docs" / "product" / "TRD.md"
UML_PATH = REPOSITORY_ROOT / "docs" / "architecture" / "UML.md"


def _read(path: Path) -> str:
    """Return one canonical documentation file as UTF-8 text."""
    return path.read_text(encoding="utf-8")


def test_trd_separates_current_staggering_from_global_deadline_target() -> None:
    """Keep PR #75's coordinator-owned deadline out of protected-main claims."""
    trd = " ".join(_read(TRD_PATH).split())

    assert "protected main does not yet enforce one coordinator-owned deadline across every coordinator wait after all candidates have started" in trd
    assert "ACTIVE-PR" in trd
    assert "one coordinator-owned absolute monotonic deadline" in trd


def test_uml_marks_global_connection_deadline_view_as_active_pr() -> None:
    """Require the global-deadline sequence diagram to declare target maturity."""
    uml = _read(UML_PATH)
    section = uml.split("## 4. Asynchronous connection-race behavior", 1)[1].split(
        "## 5. Decision-evidence production", 1
    )[0]

    assert "Maturity: **ACTIVE-PR**" in section
    assert "not protected-main behavior" in section
