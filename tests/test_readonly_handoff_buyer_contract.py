"""Buyer-facing contracts for the repository-local read-only product handoff."""

from __future__ import annotations

from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
README_PATH = REPOSITORY_ROOT / "README.md"
ARCHITECTURE_PATH = REPOSITORY_ROOT / "ARCHITECTURE.md"
ADR_PATH = (
    REPOSITORY_ROOT
    / "docs"
    / "adr"
    / "0001-security-boundaries-and-modular-integration.md"
)
CHANGELOG_PATH = REPOSITORY_ROOT / "CHANGELOG.md"


def _read(path: Path) -> str:
    """Return one repository text file as normalized UTF-8 prose."""
    return " ".join(path.read_text(encoding="utf-8").split())


def _assert_read_only_handoff_contract(text: str) -> None:
    """Require the externally promoted, credential-free product handoff boundary."""
    assert "independently reverified credential-free patch handoff" in text
    assert (
        "does not create branches, pull requests, repository writes, or auto-merge requests"
        in text
    )
    assert "external, independently reviewed, credential-separated promotion" in text
    assert "reconstruct and verify the exact tree before any repository write" in text


def test_buyer_readme_describes_the_read_only_product_handoff() -> None:
    """Keep buyer-facing scheduler claims aligned with PR #84's actual authority."""
    readme = _read(README_PATH)

    assert "A third publisher" not in readme
    assert "no direct network access" not in readme
    assert "Model web/network tools are denied" in readme
    assert "runner egress is restricted" in readme
    _assert_read_only_handoff_contract(readme)


def test_architecture_describes_the_read_only_product_handoff() -> None:
    """Keep system architecture aligned with the repository-local handoff boundary."""
    architecture = _read(ARCHITECTURE_PATH)

    assert (
        "Model execution, credential-free reverification, and publication use separate runners"
        not in architecture
    )
    _assert_read_only_handoff_contract(architecture)


def test_accepted_modular_integration_adr_describes_the_read_only_handoff() -> None:
    """Keep the accepted ADR aligned with the actual credential separation."""
    decision = _read(ADR_PATH)

    assert "before a publishing identity creates a normal pull request" not in decision
    _assert_read_only_handoff_contract(decision)


def test_changelog_records_the_buyer_facing_handoff_correction() -> None:
    """Record the compatibility-significant documentation correction in Unreleased."""
    changelog = _read(CHANGELOG_PATH)

    for fragment in (
        "buyer-facing README",
        "credential-free product scheduler boundary",
        "independently reverified exact-base/digest-bound handoff",
        "future promotion",
        "credential-separated",
    ):
        assert fragment in changelog
