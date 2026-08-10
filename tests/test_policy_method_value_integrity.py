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
