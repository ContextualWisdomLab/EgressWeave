"""Contracts for buyer-visible release, rollback, and provenance documentation."""

from __future__ import annotations

from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
PRODUCT_DOCS = REPOSITORY_ROOT / "docs" / "product"
PRD_PATH = PRODUCT_DOCS / "PRD.md"
AUDIT_PATH = PRODUCT_DOCS / "DOCUMENTATION_AUDIT.md"
RELEASE_PROVENANCE_PATH = PRODUCT_DOCS / "RELEASE_PROVENANCE.md"


def _read(path: Path) -> str:
    """Return one repository documentation file as UTF-8 text."""
    return path.read_text(encoding="utf-8")


def test_release_provenance_is_a_canonical_product_document() -> None:
    """Make release, rollback, and provenance guidance independently discoverable."""
    release_document = _read(RELEASE_PROVENANCE_PATH)

    for heading in (
        "# EgressWeave Release, Rollback, and Provenance",
        "## Protected-main release truth",
        "## Release acceptance gate",
        "## Rollback and recovery",
        "## Provenance and attestation boundary",
        "## Active-PR maturity boundary",
    ):
        assert heading in release_document

    for required_term in (
        "IMPLEMENTED-ON-PROTECTED-MAIN",
        "ACTIVE-PR",
        "docs/sealed-release-evidence.md",
        "docs/sbom-attestation-compatibility.md",
        "CHANGELOG.md",
        "rollback",
        "SLSA",
    ):
        assert required_term in release_document

    assert "does not claim" in release_document
    assert "certification" in release_document


def test_product_spine_links_the_release_provenance_document() -> None:
    """Prevent the release/provenance view from becoming an orphaned side document."""
    relative_link = "[Release, rollback, and provenance](RELEASE_PROVENANCE.md)"

    assert relative_link in _read(PRD_PATH)
    assert "[`RELEASE_PROVENANCE.md`](RELEASE_PROVENANCE.md)" in _read(AUDIT_PATH)
    assert "PRESENT-CURRENT" in _read(AUDIT_PATH)
