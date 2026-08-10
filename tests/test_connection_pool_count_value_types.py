"""Security contracts for exact connection-pool count value types."""

from __future__ import annotations

from pathlib import Path

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


def test_connection_pool_guide_documents_exact_builtin_count_values() -> None:
    """Keep operator guidance aligned with the primitive-value integrity boundary."""
    guide = Path("docs/research/connection-pool-resource-limits.md").read_text(
        encoding="utf-8"
    )

    assert "Count fields accept only exact built-in integers" in guide
    assert "integer subclasses are rejected" in guide
    assert "does not make EgressWeave a Python sandbox" in guide


def test_changelog_records_connection_count_value_sealing() -> None:
    """Record the pre-1.0 primitive-value tightening in release history."""
    changelog = Path("CHANGELOG.md").read_text(encoding="utf-8")

    assert "Reject non-exact integer subclasses in connection-pool count fields" in changelog
