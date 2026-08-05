"""Security contracts for provider-neutral outbound connection-pool limits."""

from __future__ import annotations

from dataclasses import FrozenInstanceError
from importlib import import_module
from math import inf, nan

import pytest

from egressweave import (
    EgressConnectionPoolPolicy,
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


def test_connection_pool_policy_is_immutable_and_normalizes_limits() -> None:
    """Store finite total, idle, and expiry limits without mutable state."""
    policy = EgressConnectionPoolPolicy(
        max_connections="12",
        max_keepalive_connections="4",
        keepalive_expiry_seconds=2,
    )

    assert policy.max_connections == 12
    assert policy.max_keepalive_connections == 4
    assert policy.keepalive_expiry_seconds == 2.0
    assert policy.as_dict() == {
        "max_connections": 12,
        "max_keepalive_connections": 4,
        "keepalive_expiry_seconds": 2.0,
    }
    assert not hasattr(policy, "__dict__")

    with pytest.raises(FrozenInstanceError):
        policy.max_connections = 99


def test_connection_pool_policy_defaults_match_finite_httpx_baseline() -> None:
    """Preserve prior finite pool behavior without importing HTTPX internals."""
    assert EgressConnectionPoolPolicy() == EgressConnectionPoolPolicy(
        max_connections=100,
        max_keepalive_connections=20,
        keepalive_expiry_seconds=5.0,
    )


@pytest.mark.parametrize(
    ("field_name", "value", "error_type"),
    [
        ("max_connections", True, TypeError),
        ("max_connections", object(), TypeError),
        ("max_connections", 1.5, TypeError),
        ("max_connections", 0, ValueError),
        ("max_connections", -1, ValueError),
        ("max_connections", "", ValueError),
        ("max_connections", "0", ValueError),
        ("max_connections", "+1", ValueError),
        ("max_connections", " 1", ValueError),
        ("max_connections", "１", ValueError),
        ("max_keepalive_connections", False, TypeError),
        ("max_keepalive_connections", object(), TypeError),
        ("max_keepalive_connections", 1.5, TypeError),
        ("max_keepalive_connections", -1, ValueError),
        ("max_keepalive_connections", "-1", ValueError),
        ("max_keepalive_connections", "１", ValueError),
        ("keepalive_expiry_seconds", True, TypeError),
        ("keepalive_expiry_seconds", "5", TypeError),
        ("keepalive_expiry_seconds", object(), TypeError),
        ("keepalive_expiry_seconds", -1, ValueError),
        ("keepalive_expiry_seconds", inf, ValueError),
        ("keepalive_expiry_seconds", -inf, ValueError),
        ("keepalive_expiry_seconds", nan, ValueError),
    ],
)
def test_connection_pool_policy_rejects_ambiguous_or_unbounded_values(
    field_name: str,
    value: object,
    error_type: type[Exception],
) -> None:
    """Reject values that remove, invert, or ambiguously coerce pool bounds."""
    with pytest.raises(error_type, match=field_name):
        EgressConnectionPoolPolicy(**{field_name: value})  # type: ignore[arg-type]


def test_connection_pool_policy_allows_zero_idle_retention_and_expiry() -> None:
    """Allow stricter configurations that retain no idle connection capacity."""
    policy = EgressConnectionPoolPolicy(
        max_connections=1,
        max_keepalive_connections=0,
        keepalive_expiry_seconds=0,
    )

    assert policy.max_keepalive_connections == 0
    assert policy.keepalive_expiry_seconds == 0.0


def test_connection_pool_policy_rejects_idle_capacity_above_total_capacity() -> None:
    """Reject internally contradictory pool limits during trusted startup."""
    with pytest.raises(ValueError, match="max_keepalive_connections"):
        EgressConnectionPoolPolicy(
            max_connections=4,
            max_keepalive_connections=5,
        )


def test_egress_policy_exposes_pool_policy_through_both_constructors() -> None:
    """Keep host and exact-authority builders consistent for modular callers."""
    pool_policy = EgressConnectionPoolPolicy(
        max_connections=8,
        max_keepalive_connections=2,
        keepalive_expiry_seconds=3,
    )

    host_policy = EgressPolicy.from_hosts(
        "api.example.com",
        connection_pool_policy=pool_policy,
    )
    authority_policy = EgressPolicy.from_authorities(
        [("api.example.com", 443)],
        connection_pool_policy=pool_policy,
    )

    assert host_policy.connection_pool_policy is pool_policy
    assert authority_policy.connection_pool_policy is pool_policy
    assert EgressPolicy.from_hosts(
        "api.example.com"
    ).connection_pool_policy == EgressConnectionPoolPolicy()


def test_egress_policy_rejects_unknown_pool_policy_objects() -> None:
    """Require the reviewed immutable pool contract at policy construction."""
    with pytest.raises(TypeError, match="connection_pool_policy"):
        EgressPolicy.from_hosts(
            "api.example.com",
            connection_pool_policy=object(),  # type: ignore[arg-type]
        )


def test_connection_pool_policy_changes_audit_visible_fingerprints() -> None:
    """Make connection-capacity policy drift detectable in decision evidence."""
    validated = _validated_result()
    narrower = EgressPolicy.from_hosts(
        "api.example.com",
        connection_pool_policy=EgressConnectionPoolPolicy(
            max_connections=4, max_keepalive_connections=4
        ),
    )
    wider = EgressPolicy.from_hosts(
        "api.example.com",
        connection_pool_policy=EgressConnectionPoolPolicy(
            max_connections=8, max_keepalive_connections=4
        ),
    )

    narrower_evidence = build_egress_decision_evidence(validated, policy=narrower)
    wider_evidence = build_egress_decision_evidence(validated, policy=wider)

    assert narrower_evidence.policy_fingerprint != wider_evidence.policy_fingerprint
    assert narrower_evidence.decision_fingerprint != wider_evidence.decision_fingerprint


def test_sync_transport_injects_exact_connection_pool_limits(monkeypatch) -> None:
    """Construct the synchronous HTTPCore pool from only reviewed policy data."""
    observed: dict[str, object] = {}

    class CapturingPool:
        """Capture synchronous connection-pool constructor arguments."""

        def __init__(self, **kwargs: object) -> None:
            """Record all delegated pool controls."""
            observed.update(kwargs)

    monkeypatch.setattr(sync_transport_module.httpcore, "ConnectionPool", CapturingPool)
    pool_policy = EgressConnectionPoolPolicy(
        max_connections=7,
        max_keepalive_connections=3,
        keepalive_expiry_seconds=1.25,
    )
    policy = EgressPolicy.from_hosts(
        "api.example.com",
        connection_pool_policy=pool_policy,
    )

    sync_transport_module._PinnedEgressTransport(_validated_result(), policy)

    assert observed["max_connections"] == 7
    assert observed["max_keepalive_connections"] == 3
    assert observed["keepalive_expiry"] == 1.25
    assert observed["http1"] is True
    assert observed["http2"] is False


def test_async_transport_injects_exact_connection_pool_limits(monkeypatch) -> None:
    """Construct the asynchronous HTTPCore pool from reviewed policy data."""
    observed: dict[str, object] = {}

    class CapturingPool:
        """Capture asynchronous connection-pool constructor arguments."""

        def __init__(self, **kwargs: object) -> None:
            """Record all delegated pool controls."""
            observed.update(kwargs)

    monkeypatch.setattr(
        async_transport_module.httpcore,
        "AsyncConnectionPool",
        CapturingPool,
    )
    pool_policy = EgressConnectionPoolPolicy(
        max_connections=9,
        max_keepalive_connections=1,
        keepalive_expiry_seconds=0.5,
    )
    policy = EgressPolicy.from_hosts(
        "api.example.com",
        connection_pool_policy=pool_policy,
    )

    async_transport_module._PinnedEgressAsyncTransport(_validated_result(), policy)

    assert observed["max_connections"] == 9
    assert observed["max_keepalive_connections"] == 1
    assert observed["keepalive_expiry"] == 0.5
    assert observed["http1"] is True
    assert observed["http2"] is False


def test_transports_do_not_import_httpx_private_default_limits() -> None:
    """Keep connection policy provider-neutral instead of HTTPX-default-coupled."""
    sync_source = sync_transport_module.__file__
    async_source = async_transport_module.__file__
    assert sync_source is not None
    assert async_source is not None

    with open(sync_source, encoding="utf-8") as source_file:
        assert "DEFAULT_LIMITS" not in source_file.read()
    with open(async_source, encoding="utf-8") as source_file:
        assert "DEFAULT_LIMITS" not in source_file.read()


def test_connection_pool_policy_is_exported_from_public_package() -> None:
    """Expose the stable policy type to standalone and modular integrations."""
    package = import_module("egressweave")

    assert package.EgressConnectionPoolPolicy is EgressConnectionPoolPolicy
    assert "EgressConnectionPoolPolicy" in package.__all__
