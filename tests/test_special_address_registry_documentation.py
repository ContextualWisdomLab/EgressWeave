"""Documentation contracts for version-stable special-purpose address handling."""

from __future__ import annotations

from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
RESEARCH_INDEX = REPOSITORY_ROOT / "docs" / "research" / "README.md"
SPECIAL_ADDRESS_GUIDE = (
    REPOSITORY_ROOT / "docs" / "research" / "special-purpose-address-classification.md"
)
CHANGELOG = REPOSITORY_ROOT / "CHANGELOG.md"


def _read(path: Path) -> str:
    """Return one repository text file as UTF-8."""
    return path.read_text(encoding="utf-8")


def test_special_address_compatibility_has_primary_source_guidance() -> None:
    """Require the compatibility overlay and its standards boundary to be documented."""
    guide = _read(SPECIAL_ADDRESS_GUIDE)

    required_fragments = (
        "reviewed compatibility overlay",
        "IANA IPv4 Special-Purpose Address Space",
        "IANA IPv6 Special-Purpose Address Space",
        "Python 3.14.6",
        "192.0.0.9/32",
        "2001:1::3/128",
        "2002::/16",
        "Globally Reachable` is `N/A",
        "no runtime registry download",
        "Internet Assigned Numbers Authority. (2025, October 9).",
        "Python Software Foundation. (2026).",
    )
    missing = [fragment for fragment in required_fragments if fragment not in guide]
    assert not missing, f"special-address guidance is missing: {missing}"


def test_research_index_links_special_address_compatibility_guidance() -> None:
    """Keep the version-sensitive address-classification boundary discoverable."""
    research_index = _read(RESEARCH_INDEX)

    assert "special-purpose-address-classification.md" in research_index
    assert "version-stable special-purpose address classification" in research_index


def test_changelog_records_special_address_compatibility_hardening() -> None:
    """Keep the security compatibility change visible in release-facing history."""
    changelog = " ".join(_read(CHANGELOG).split())

    assert "special-purpose address classification" in changelog
    assert "interpreter patch-level" in changelog
    assert "reviewed compatibility overlay" in changelog
