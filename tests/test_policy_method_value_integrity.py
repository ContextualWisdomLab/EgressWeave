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
