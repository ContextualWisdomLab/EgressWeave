"""Contracts keeping special-purpose address policy and shipped guidance aligned."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GUIDE = ROOT / "docs" / "research" / "special-purpose-address-classification.md"
RESEARCH_INDEX = ROOT / "docs" / "research" / "README.md"
VALIDATION = ROOT / "src" / "egressweave" / "validation.py"


def test_special_purpose_policy_has_discoverable_current_primary_source_guidance() -> None:
    """Keep the compatibility policy discoverable and grounded in current sources."""
    guide = GUIDE.read_text(encoding="utf-8")
    index = RESEARCH_INDEX.read_text(encoding="utf-8")

    for fragment in (
        "Version-stable special-purpose address classification",
        "no runtime registry download",
        "IANA IPv4 Special-Purpose Address Space",
        "IANA IPv6 Special-Purpose Address Space",
        "Python 3.14 documentation",
        "40d75c2b7f5c67e254d0a025e0f2e2c7ada7f69f",
        "2001:1::3/128",
        "2002::/16",
    ):
        assert fragment in guide

    assert "special-purpose-address-classification.md" in index


def test_documented_compatibility_ranges_match_source_controlled_overlay() -> None:
    """Prevent silent drift between the reviewed guide and implementation constants."""
    guide = GUIDE.read_text(encoding="utf-8")
    source = VALIDATION.read_text(encoding="utf-8")

    source_controlled_networks = (
        "192.0.0.0/24",
        "192.0.0.9/32",
        "192.0.0.10/32",
        "64:ff9b:1::/48",
        "100:0:0:1::/64",
        "2001::/23",
        "2001:1::1/128",
        "2001:1::2/128",
        "2001:1::3/128",
        "2001:3::/32",
        "2001:4:112::/48",
        "2001:20::/28",
        "2001:30::/28",
        "2002::/16",
        "3fff::/20",
        "5f00::/16",
    )
    for network in source_controlled_networks:
        assert network in guide
        assert network in source

    # The guide calls out this IANA child allocation explicitly, while the
    # implementation denies it through the reviewed broader 2001::/23 parent.
    assert "2001:2::/48" in guide
    assert "2001::/23" in source
