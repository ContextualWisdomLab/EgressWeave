"""Regression tests for exact built-in HTTP method policy values."""

from __future__ import annotations

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
    """Expose polymorphic dispatch in comma-separated method parsing."""

    def split(self, sep: str | None = None, maxsplit: int = -1) -> list[str]:
        """Fail if trusted construction invokes subclass-controlled splitting."""
        raise AssertionError("string subclass split executed")


def test_method_policy_rejects_str_subclass_before_normalization() -> None:
    """Reject subclass-controlled method normalization during policy construction."""
    with pytest.raises(TypeError, match="allowed_methods"):
        EgressPolicy.from_hosts(
            "api.example.com",
            allowed_methods={_NonExactMethod("GET")},
        )


def test_direct_policy_rejects_str_subclass_before_comma_split() -> None:
    """Reject a direct comma-string subclass before invoking its split method."""
    with pytest.raises(TypeError, match="allowed_methods"):
        EgressPolicy(
            allowed_hosts=frozenset({"api.example.com"}),
            allowed_methods=_ExplodingMethodList("GET,POST"),
        )


def test_from_hosts_rejects_str_subclass_before_comma_split() -> None:
    """Reject a host-factory comma-string subclass before invoking split."""
    with pytest.raises(TypeError, match="allowed_methods"):
        EgressPolicy.from_hosts(
            "api.example.com",
            allowed_methods=_ExplodingMethodList("GET,POST"),
        )


def test_from_authorities_rejects_str_subclass_before_comma_split() -> None:
    """Reject an authority-factory comma-string subclass before invoking split."""
    with pytest.raises(TypeError, match="allowed_methods"):
        EgressPolicy.from_authorities(
            [("api.example.com", 443)],
            allowed_methods=_ExplodingMethodList("GET,POST"),
        )
