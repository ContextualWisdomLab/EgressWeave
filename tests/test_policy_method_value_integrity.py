"""Regression tests for exact built-in HTTP method policy values."""

from __future__ import annotations

from pathlib import Path

import pytest

from egressweave.policy import EgressPolicy


class _NonExactMethod(str):
    """Keep subclass identity if trusted normalization invokes polymorphic methods."""

    def strip(self, chars: str | None = None) -> _NonExactMethod:
        """Return this subclass instead of a canonical built-in string."""
        return self

    def upper(self) -> _NonExactMethod:
        """Return this subclass instead of a canonical built-in string."""
        return self


class _ExplodingMethodList(str):
    """Expose unsafe polymorphic dispatch in comma-separated method parsing."""

    def split(self, sep: str | None = None, maxsplit: int = -1) -> list[str]:
        """Fail if trusted construction invokes subclass-controlled splitting."""
        raise AssertionError("string subclass split executed")


def test_method_policy_rejects_str_subclass_before_normalization() -> None:
    """Reject subclass-controlled method normalization during policy construction."""
    with pytest.raises(
        TypeError,
        match="^allowed_methods entries must be HTTP method strings$",
    ):
        EgressPolicy.from_hosts(
            "api.example.com",
            allowed_methods={_NonExactMethod("GET")},
        )


def test_direct_policy_rejects_str_subclass_before_comma_split() -> None:
    """Reject a direct comma-string subclass before invoking its split method."""
    with pytest.raises(
        TypeError,
        match="^allowed_methods entries must be HTTP method strings$",
    ):
        EgressPolicy(
            allowed_hosts=frozenset({"api.example.com"}),
            allowed_methods=_ExplodingMethodList("GET,POST"),
        )


def test_from_hosts_rejects_str_subclass_before_comma_split() -> None:
    """Reject a host-factory comma-string subclass before invoking split."""
    with pytest.raises(
        TypeError,
        match="^allowed_methods entries must be HTTP method strings$",
    ):
        EgressPolicy.from_hosts(
            "api.example.com",
            allowed_methods=_ExplodingMethodList("GET,POST"),
        )


def test_from_authorities_rejects_str_subclass_before_comma_split() -> None:
    """Reject an authority-factory comma-string subclass before invoking split."""
    with pytest.raises(
        TypeError,
        match="^allowed_methods entries must be HTTP method strings$",
    ):
        EgressPolicy.from_authorities(
            [("api.example.com", 443)],
            allowed_methods=_ExplodingMethodList("GET,POST"),
        )


def test_policy_configuration_integrity_guide_covers_exact_method_strings() -> None:
    """Document the exact HTTP method value boundary and preserved string syntax."""
    guide = Path("docs/research/policy-configuration-integrity.md").read_text(
        encoding="utf-8"
    )

    assert "exact built-in `str`" in guide
    assert "HTTP method" in guide
    assert "comma-separated" in guide
    assert "does not make EgressWeave a Python sandbox" in guide


def test_changelog_records_http_method_value_sealing() -> None:
    """Record the method-string policy tightening in release history."""
    changelog = Path("CHANGELOG.md").read_text(encoding="utf-8")

    assert "Reject non-exact string subclasses in HTTP method policy values" in changelog
