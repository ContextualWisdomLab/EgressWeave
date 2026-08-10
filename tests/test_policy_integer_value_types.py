"""Security contracts for exact built-in integer policy values."""

from __future__ import annotations

from pathlib import Path

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


def test_policy_configuration_integrity_guide_is_discoverable_and_current() -> None:
    """Document the supported primitive-value boundary without sandbox claims."""
    guide_path = Path("docs/research/policy-configuration-integrity.md")

    assert guide_path.is_file()
    guide = guide_path.read_text(encoding="utf-8")
    assert "exact built-in `int`" in guide
    assert "ASCII decimal strings" in guide
    assert "does not make EgressWeave a Python sandbox" in guide
    assert "https://docs.python.org/3.14/reference/datamodel.html" in guide


def test_changelog_records_shared_policy_integer_value_sealing() -> None:
    """Record the trusted scalar policy tightening in release history."""
    changelog = Path("CHANGELOG.md").read_text(encoding="utf-8")

    assert "Reject non-exact integer subclasses in shared policy integer fields" in changelog
