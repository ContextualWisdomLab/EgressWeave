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

    protected_main = document.split("## Protected-main release truth", 1)[1].split(
        "## Active-PR maturity boundary",
        1,
    )[0]
    assert "credential-bearing handoff consumer is an" not in protected_main
    assert (
        "protected-main release workflow does not consume the credential-bearing handoff"
        in protected_main
    )
    assert "The repository-level verifier is deliberately credential free" in protected_main


def test_credentialed_handoff_revalidation_is_explicitly_active_pr() -> None:
    """Require future handoff consumption to retain the full ACTIVE-PR trust contract."""
    document = _read_release_provenance()

    active_pr = document.split("## Active-PR maturity boundary", 1)[1].split(
        "## Ownership boundary",
        1,
    )[0]
    assert (
        "credential-bearing handoff consumer is an **ACTIVE-PR target**, "
        "not protected-main behavior"
    ) in active_pr
    required_handoff_claims = (
        "sealed handoff",
        "source commit",
        "source-identity digest",
        "checksum digest",
        "payload cardinality",
        "every payload digest",
        "must not rebuild",
        "resolve dependencies",
        "import distributions",
        "execute caller-controlled source",
        "`id-token: write`",
        "`attestations: write`",
        "package-publication",
        "release",
        "tag",
        "repository-write",
    )
    for claim in required_handoff_claims:
        assert claim in active_pr
