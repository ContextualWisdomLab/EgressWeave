"""Security contracts for exact connection-pool count value types."""

from __future__ import annotations

import pytest

from egressweave import EgressConnectionPoolPolicy


class _ConnectionCountSubclass(int):
    """Represent an unreviewed integer subclass crossing trusted configuration."""


@pytest.mark.parametrize(
    "field_name",
    ["max_connections", "max_keepalive_connections"],
)
def test_connection_pool_policy_rejects_integer_subclasses(field_name: str) -> None:
    """Reject non-exact integers before retaining finite pool-capacity values."""
    with pytest.raises(TypeError, match=field_name):
        EgressConnectionPoolPolicy(
            **{field_name: _ConnectionCountSubclass(1)}  # type: ignore[arg-type]
        )


def test_connection_pool_policy_keeps_reviewed_count_input_forms() -> None:
    """Continue accepting exact integers and reviewed ASCII decimal strings."""
    exact_integer = EgressConnectionPoolPolicy(
        max_connections=8,
        max_keepalive_connections=2,
    )
    decimal_string = EgressConnectionPoolPolicy(
        max_connections="8",
        max_keepalive_connections="2",
    )

    assert type(exact_integer.max_connections) is int
    assert type(exact_integer.max_keepalive_connections) is int
    assert decimal_string == exact_integer
    assert type(decimal_string.max_connections) is int
    assert type(decimal_string.max_keepalive_connections) is int
