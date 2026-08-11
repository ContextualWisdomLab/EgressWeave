"""Regression tests for exact built-in integer policy inputs."""

from __future__ import annotations

import pytest

from egressweave import EgressPolicy


class _IntegerSubclass(int):
    """Exercise Python integer subclass handling at policy construction."""


def test_port_rejects_integer_subclass() -> None:
    """Require an exact integer for an allowed port."""
    with pytest.raises(TypeError, match="allowed_ports"):
        EgressPolicy.from_hosts("api.example.com", allowed_ports=[_IntegerSubclass(443)])


def test_dns_limit_rejects_integer_subclass() -> None:
    """Require an exact integer for the DNS candidate limit."""
    with pytest.raises(TypeError, match="max_resolved_addresses"):
        EgressPolicy.from_hosts(
            "api.example.com", max_resolved_addresses=_IntegerSubclass(8)
        )


def test_header_count_rejects_integer_subclass() -> None:
    """Require an exact integer for a header-count limit."""
    with pytest.raises(TypeError, match="max_request_header_fields"):
        EgressPolicy.from_hosts(
            "api.example.com", max_request_header_fields=_IntegerSubclass(8)
        )


def test_body_budget_rejects_integer_subclass() -> None:
    """Require an exact integer for a byte-budget limit."""
    with pytest.raises(TypeError, match="max_request_bytes"):
        EgressPolicy.from_hosts("api.example.com", max_request_bytes=_IntegerSubclass(4096))
