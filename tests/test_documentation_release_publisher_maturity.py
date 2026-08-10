"""Maturity contracts for release handoff consumption and publication."""

from __future__ import annotations

from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
RELEASE_PROVENANCE_PATH = REPOSITORY_ROOT / "docs" / "product" / "RELEASE_PROVENANCE.md"


def _read_release_provenance() -> str:
    """Return the canonical release/provenance guide as UTF-8 text."""
    return RELEASE_PROVENANCE_PATH.read_text(encoding="utf-8")


def test_protected_main_does_not_claim_handoff_consuming_publisher() -> None:
    """Keep credentialed handoff consumption out of protected-main release truth."""
    document = _read_release_provenance()

    protected_main = document.split("## Release acceptance gate", 1)[1].split(
        "## Rollback and recovery",
        1,
    )[0]
    assert "credential-bearing attestation or publisher consumes" not in protected_main
    assert "protected-main release workflow does not consume" in protected_main


def test_credentialed_handoff_revalidation_is_explicitly_active_pr() -> None:
    """Require future handoff consumption to retain an ACTIVE-PR maturity label."""
    document = _read_release_provenance()

    active_pr = document.split("## Active-PR maturity boundary", 1)[1].split(
        "## Ownership boundary",
        1,
    )[0]
    assert "credential-bearing handoff consumer" in active_pr
    assert "recheck the exact repository/source identity and every payload digest" in active_pr
