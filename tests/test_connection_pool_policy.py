"""Security contracts for finite synchronous and asynchronous connection pools."""

from __future__ import annotations

from dataclasses import FrozenInstanceError
from importlib import import_module
from math import inf, nan

import pytest

from egressweave import (
    EgressConnectionPolicy,
    EgressPolicy,
    build_egress_decision_evidence,
)
from egressweave import sync_transport as sync_transport_module
from egressweave import transport as async_transport_module
from egressweave.validation import _make_validated_egress_url


def _validated_result():
    """Return one signed public HTTPS destination for transport tests."""
    return _make_validated_egress_url(
        "https://api.example.com/v1/models",
        "api.example.com",
        443,
        ("93.184.216.34",),
    )


def test_connection_policy_is_immutable_and_normalizes_finite_limits() -> None:
    """Store explicit pool cardinality and idle-retention limits immutably."""
    policy = EgressConnectionPolicy(
        max_connections="7",
        max_keepalive_connections="3",
        keepalive_expiry_seconds=2,
    )

    assert policy.max_connections == 7
    assert policy.max_keepalive_connections == 3
    assert policy.keepalive_expiry_seconds == 2.0
    assert policy.as_httpcore_limits() == {
        "max_connections": 7,
        "max_keepalive_connections": 3,
        "keepalive_expiry": 2.0,
    }
    assert not hasattr(policy, "__dict__")

    with pytest.raises(FrozenInstanceError):
        policy.max_connections = 99


@pytest.mark.parametrize(
    ("field_name", "value", "error_type"),
    [
        ("max_connections", True, TypeError),
        ("max_connections", 1.5, TypeError),
        ("max_connections", object(), TypeError),
        ("max_connections", "", ValueError),
        ("max_connections", "seven", ValueError),
        ("max_connections", "０", ValueError),
        ("max_connections", 0, ValueError),
        ("max_connections", -1, ValueError),
        ("max_keepalive_connections", True, TypeError),
        ("max_keepalive_connections", 1.5, TypeError),
        ("max_keepalive_connections", object(), TypeError),
        ("max_keepalive_connections", "", ValueError),
        ("max_keepalive_connections", "many", ValueError),
        ("max_keepalive_connections", -1, ValueError),
        ("keepalive_expiry_seconds", True, TypeError),
        ("keepalive_expiry_seconds", "5", TypeError),
        ("keepalive_expiry_seconds", object(), TypeError),
        ("keepalive_expiry_seconds", -1, ValueError),
        ("keepalive_expiry_seconds", inf, ValueError),
        ("keepalive_expiry_seconds", -inf, ValueError),
        ("keepalive_expiry_seconds", nan, ValueError),
    ],
)
def test_connection_policy_rejects_unbounded_or_ambiguous_limits(
    field_name: str,
    value: object,
    error_type: type[Exception],
) -> None:
    """Reject settings that could remove or ambiguously coerce a pool bound."""
    with pytest.raises(error_type, match=field_name):
        EgressConnectionPolicy(**{field_name: value})  # type: ignore[arg-type]


def test_zero_keepalive_capacity_and_expiry_are_explicitly_supported() -> None:
    """Permit operators to disable idle connection retention without disabling bounds."""
    policy = EgressConnectionPolicy(
        max_connections=1,
        max_keepalive_connections=0,
        keepalive_expiry_seconds=0,
    )

    assert policy.as_httpcore_limits() == {
        "max_connections": 1,
        "max_keepalive_connections": 0,
        "keepalive_expiry": 0.0,
    }


def test_keepalive_capacity_must_not_exceed_total_capacity() -> None:
    """Reject contradictory pool settings rather than relying on silent clamping."""
    with pytest.raises(ValueError, match="max_keepalive_connections"):
        EgressConnectionPolicy(
            max_connections=2,
            max_keepalive_connections=3,
        )


def test_egress_policy_exposes_connection_policy_through_both_constructors() -> None:
    """Keep host and exact-authority builders consistent for modular callers."""
    connection_policy = EgressConnectionPolicy(
        max_connections=7,
        max_keepalive_connections=2,
        keepalive_expiry_seconds=1.5,
    )

    host_policy = EgressPolicy.from_hosts(
        "api.example.com",
        connection_policy=connection_policy,
    )
    authority_policy = EgressPolicy.from_authorities(
        [("api.example.com", 443)],
        connection_policy=connection_policy,
    )

    assert host_policy.connection_policy is connection_policy
    assert authority_policy.connection_policy is connection_policy
    assert EgressPolicy.from_hosts(
        "api.example.com"
    ).connection_policy == EgressConnectionPolicy()


def test_egress_policy_rejects_unknown_connection_policy_objects() -> None:
    """Require the reviewed immutable pool contract at policy construction."""
    with pytest.raises(TypeError, match="connection_policy"):
        EgressPolicy.from_hosts(
            "api.example.com",
            connection_policy=object(),  # type: ignore[arg-type]
        )


def test_connection_policy_changes_audit_visible_policy_fingerprints() -> None:
    """Make connection-allocation policy drift detectable in decision evidence."""
    validated = _validated_result()
    smaller = EgressPolicy.from_hosts(
        "api.example.com",
        connection_policy=EgressConnectionPolicy(max_connections=7),
    )
    larger = EgressPolicy.from_hosts(
        "api.example.com",
        connection_policy=EgressConnectionPolicy(max_connections=8),
    )

    smaller_evidence = build_egress_decision_evidence(validated, policy=smaller)
    larger_evidence = build_egress_decision_evidence(validated, policy=larger)

    assert smaller_evidence.policy_fingerprint != larger_evidence.policy_fingerprint
    assert smaller_evidence.decision_fingerprint != larger_evidence.decision_fingerprint


def test_sync_transport_uses_only_injected_connection_pool_limits() -> None:
    """Apply explicit finite connection limits to the synchronous HTTPCore pool."""
    policy = EgressPolicy.from_hosts(
        "api.example.com",
        connection_policy=EgressConnectionPolicy(
            max_connections=7,
            max_keepalive_connections=3,
            keepalive_expiry_seconds=2.5,
        ),
    )
    transport = sync_transport_module._PinnedEgressTransport(
        _validated_result(),
        policy,
    )

    try:
        assert transport._pool._max_connections == 7
        assert transport._pool._max_keepalive_connections == 3
        assert transport._pool._keepalive_expiry == 2.5
    finally:
        transport.close()


@pytest.mark.asyncio
async def test_async_transport_uses_only_injected_connection_pool_limits() -> None:
    """Apply explicit finite connection limits to the asynchronous HTTPCore pool."""
    policy = EgressPolicy.from_hosts(
        "api.example.com",
        connection_policy=EgressConnectionPolicy(
            max_connections=11,
            max_keepalive_connections=4,
            keepalive_expiry_seconds=3.5,
        ),
    )
    transport = async_transport_module._PinnedEgressAsyncTransport(
        _validated_result(),
        policy,
    )

    try:
        assert transport._pool._max_connections == 11
        assert transport._pool._max_keepalive_connections == 4
        assert transport._pool._keepalive_expiry == 3.5
    finally:
        await transport.aclose()


def test_public_package_exports_connection_policy() -> None:
    """Expose the pool-bound contract through the stable package surface."""
    package = import_module("egressweave")

    assert package.EgressConnectionPolicy is EgressConnectionPolicy
    assert "EgressConnectionPolicy" in package.__all__
