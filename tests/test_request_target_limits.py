"""Security contracts for finite outbound request-target budgets."""

from __future__ import annotations

import pytest

from egressweave._policy_normalization import (
    DEFAULT_MAX_REQUEST_TARGET_BYTES,
    _normalize_max_request_target_bytes,
)


def test_request_target_budget_has_finite_default() -> None:
    """Protect integrations even before public policy wiring is complete."""
    assert DEFAULT_MAX_REQUEST_TARGET_BYTES == 8 * 1024


@pytest.mark.parametrize("value", [1, 8192, "1", "8192"])
def test_request_target_budget_normalizes_positive_values(value: int | str) -> None:
    """Accept positive integers and ASCII decimal environment text."""
    assert _normalize_max_request_target_bytes(value) == int(value)


@pytest.mark.parametrize(
    ("value", "error_type"),
    [
        (True, TypeError),
        (1.5, TypeError),
        (object(), TypeError),
        (0, ValueError),
        (-1, ValueError),
        ("", ValueError),
        ("+1", ValueError),
        ("-1", ValueError),
        ("1.5", ValueError),
        ("１", ValueError),
    ],
)
def test_request_target_budget_rejects_ambiguous_or_unbounded_configuration(
    value: object,
    error_type: type[Exception],
) -> None:
    """Fail during trusted normalization instead of disabling the limit."""
    with pytest.raises(error_type, match="max_request_target_bytes"):
        _normalize_max_request_target_bytes(value)
