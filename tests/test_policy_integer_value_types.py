"""Security contracts for exact built-in integer policy values."""

from __future__ import annotations

import pytest

from egressweave import EgressPolicy


class _PolicyIntegerSubclass(int):
    """Represent an unreviewed integer subclass crossing trusted configuration."""


def test_policy_rejects_integer_subclass_for_allowed_port() -> None:
    """Reject non-exact ports before retaining normalized authority state."""
    with pytest.raises(TypeError, match="allowed_ports"):
        EgressPolicy.from_hosts(
            "api.example.com",
            allowed_ports=[_PolicyIntegerSubclass(443)],
        )


@pytest.mark.parametrize(
    "field_name",
    [
        "max_resolved_addresses",
        "max_request_header_fields",
        "max_request_bytes",
    ],
)
def test_policy_rejects_integer_subclass_for_resource_limits(field_name: str) -> None:
    """Reject non-exact integers before retaining finite resource limits."""
    with pytest.raises(TypeError, match=field_name):
        EgressPolicy.from_hosts(
            "api.example.com",
            **{field_name: _PolicyIntegerSubclass(8)},  # type: ignore[arg-type]
        )


def test_policy_keeps_exact_integer_and_decimal_string_configuration() -> None:
    """Preserve reviewed exact integers and decimal environment values."""
    exact_integer = EgressPolicy.from_hosts(
        "api.example.com",
        allowed_ports=[8443],
        max_resolved_addresses=8,
        max_request_header_fields=32,
        max_request_bytes=4096,
    )
    decimal_string = EgressPolicy.from_hosts(
        "api.example.com",
        allowed_ports=["8443"],
        max_resolved_addresses="8",
        max_request_header_fields="32",
        max_request_bytes="4096",
    )

    assert decimal_string == exact_integer
    assert all(type(port) is int for port in decimal_string.allowed_ports)
    assert type(decimal_string.max_resolved_addresses) is int
    assert type(decimal_string.max_request_header_fields) is int
    assert type(decimal_string.max_request_bytes) is int
