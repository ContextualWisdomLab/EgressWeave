"""Security contracts for transport-enforced outbound request timeouts."""

from __future__ import annotations

from dataclasses import FrozenInstanceError
from importlib import import_module
from math import inf, nan

import httpx
import pytest

from egressweave import (
    EGRESS_NOT_ALLOWED,
    EgressNotAllowedError,
    EgressPolicy,
    EgressTimeoutPolicy,
    build_egress_decision_evidence,
)
from egressweave import sync_transport as sync_transport_module
from egressweave import transport as async_transport_module
from egressweave.request_safety import _bind_bounded_request_timeouts
from egressweave.validation import _make_validated_egress_url


class _StopSyncDispatch(RuntimeError):
    """Stop a synchronous transport after its HTTPCore request is captured."""


class _StopAsyncDispatch(RuntimeError):
    """Stop an asynchronous transport after its HTTPCore request is captured."""


def _validated_result():
    """Return one signed public HTTPS destination for transport tests."""
    return _make_validated_egress_url(
        "https://api.example.com/v1/models",
        "api.example.com",
        443,
        ("93.184.216.34",),
    )


def test_timeout_policy_is_immutable_and_normalizes_finite_maxima() -> None:
    """Store four positive finite timeout ceilings as immutable floats."""
    policy = EgressTimeoutPolicy(
        connect_timeout_seconds=1,
        read_timeout_seconds=2.5,
        write_timeout_seconds=3,
        pool_timeout_seconds=4.5,
    )

    assert policy.connect_timeout_seconds == 1.0
    assert policy.read_timeout_seconds == 2.5
    assert policy.write_timeout_seconds == 3.0
    assert policy.pool_timeout_seconds == 4.5
    assert not hasattr(policy, "__dict__")

    with pytest.raises(FrozenInstanceError):
        policy.read_timeout_seconds = 99.0


@pytest.mark.parametrize(
    ("field_name", "value", "error_type"),
    [
        ("connect_timeout_seconds", True, TypeError),
        ("read_timeout_seconds", "5", TypeError),
        ("write_timeout_seconds", object(), TypeError),
        ("pool_timeout_seconds", 0, ValueError),
        ("connect_timeout_seconds", -1, ValueError),
        ("read_timeout_seconds", inf, ValueError),
        ("write_timeout_seconds", -inf, ValueError),
        ("pool_timeout_seconds", nan, ValueError),
    ],
)
def test_timeout_policy_rejects_unbounded_or_ambiguous_maxima(
    field_name: str,
    value: object,
    error_type: type[Exception],
) -> None:
    """Reject settings that could remove or ambiguously coerce a phase bound."""
    with pytest.raises(error_type, match=field_name):
        EgressTimeoutPolicy(**{field_name: value})  # type: ignore[arg-type]


def test_egress_policy_exposes_timeout_policy_through_both_constructors() -> None:
    """Keep host and exact-authority builders consistent for modular callers."""
    timeout_policy = EgressTimeoutPolicy(
        connect_timeout_seconds=2,
        read_timeout_seconds=3,
        write_timeout_seconds=4,
        pool_timeout_seconds=1,
    )

    host_policy = EgressPolicy.from_hosts(
        "api.example.com",
        request_timeout_policy=timeout_policy,
    )
    authority_policy = EgressPolicy.from_authorities(
        [("api.example.com", 443)],
        request_timeout_policy=timeout_policy,
    )

    assert host_policy.request_timeout_policy is timeout_policy
    assert authority_policy.request_timeout_policy is timeout_policy
    assert EgressPolicy.from_hosts(
        "api.example.com"
    ).request_timeout_policy == EgressTimeoutPolicy()


def test_egress_policy_rejects_unknown_timeout_policy_objects() -> None:
    """Require the reviewed immutable timeout contract at policy construction."""
    with pytest.raises(TypeError, match="request_timeout_policy"):
        EgressPolicy.from_hosts(
            "api.example.com",
            request_timeout_policy=object(),  # type: ignore[arg-type]
        )


def test_missing_or_disabled_request_timeouts_receive_policy_maxima() -> None:
    """Replace omitted and explicitly disabled phase timeouts with finite caps."""
    policy = EgressTimeoutPolicy(
        connect_timeout_seconds=2,
        read_timeout_seconds=3,
        write_timeout_seconds=4,
        pool_timeout_seconds=1,
    )

    missing = _bind_bounded_request_timeouts({}, policy)
    disabled = _bind_bounded_request_timeouts({"timeout": None}, policy)

    expected = {
        "connect": 2.0,
        "read": 3.0,
        "write": 4.0,
        "pool": 1.0,
    }
    assert missing["timeout"] == expected
    assert disabled["timeout"] == expected


def test_request_timeouts_preserve_stricter_values_and_cap_larger_values() -> None:
    """Honor caller deadlines only when they are no weaker than policy maxima."""
    marker = object()
    requested_timeouts = {
        "connect": 60.0,
        "read": 0.5,
        "write": None,
        "pool": 0,
    }
    extensions = {"timeout": requested_timeouts, "trace": marker}
    policy = EgressTimeoutPolicy(
        connect_timeout_seconds=2,
        read_timeout_seconds=3,
        write_timeout_seconds=4,
        pool_timeout_seconds=1,
    )

    bounded = _bind_bounded_request_timeouts(extensions, policy)

    assert bounded["timeout"] == {
        "connect": 2.0,
        "read": 0.5,
        "write": 4.0,
        "pool": 0.0,
    }
    assert bounded["trace"] is marker
    assert bounded is not extensions
    assert bounded["timeout"] is not requested_timeouts
    assert requested_timeouts == {
        "connect": 60.0,
        "read": 0.5,
        "write": None,
        "pool": 0,
    }


@pytest.mark.parametrize(
    "timeout_extension",
    [
        5,
        "5",
        [],
        {"connect": True},
        {"connect": -1},
        {"connect": inf},
        {"connect": -inf},
        {"connect": nan},
        {"connect": object()},
        {"unknown": 1},
        {b"connect": 1},
    ],
)
def test_malformed_request_timeout_extensions_fail_with_generic_denial(
    timeout_extension: object,
) -> None:
    """Fail closed before malformed low-level timeout metadata reaches HTTPCore."""
    with pytest.raises(
        EgressNotAllowedError,
        match=f"^{EGRESS_NOT_ALLOWED}$",
    ) as error:
        _bind_bounded_request_timeouts(
            {"timeout": timeout_extension},
            EgressTimeoutPolicy(),
        )

    assert error.value.__cause__ is None


def test_timeout_policy_changes_audit_visible_policy_fingerprints() -> None:
    """Make request-phase resource-policy drift detectable in decision evidence."""
    validated = _validated_result()
    shorter = EgressPolicy.from_hosts(
        "api.example.com",
        request_timeout_policy=EgressTimeoutPolicy(read_timeout_seconds=2),
    )
    longer = EgressPolicy.from_hosts(
        "api.example.com",
        request_timeout_policy=EgressTimeoutPolicy(read_timeout_seconds=4),
    )

    shorter_evidence = build_egress_decision_evidence(validated, policy=shorter)
    longer_evidence = build_egress_decision_evidence(validated, policy=longer)

    assert shorter_evidence.policy_fingerprint != longer_evidence.policy_fingerprint
    assert shorter_evidence.decision_fingerprint != longer_evidence.decision_fingerprint


def test_sync_transport_binds_timeout_ceilings_before_pool_dispatch() -> None:
    """Pass only policy-bounded timeout metadata into synchronous HTTPCore."""
    observed: dict[str, object] = {}

    class CapturingPool:
        """Capture one core request without performing network I/O."""

        def handle_request(self, request) -> None:
            """Record sanitized extensions and stop dispatch."""
            observed["extensions"] = request.extensions
            raise _StopSyncDispatch

        def close(self) -> None:
            """Close the inert pool."""

    timeout_policy = EgressTimeoutPolicy(
        connect_timeout_seconds=2,
        read_timeout_seconds=3,
        write_timeout_seconds=4,
        pool_timeout_seconds=1,
    )
    policy = EgressPolicy.from_hosts(
        "api.example.com",
        request_timeout_policy=timeout_policy,
    )
    transport = sync_transport_module._PinnedEgressTransport(
        _validated_result(),
        policy,
    )
    transport._pool.close()
    transport._pool = CapturingPool()  # type: ignore[assignment]
    request = httpx.Request(
        "POST",
        "https://api.example.com/v1/models",
        content=b"payload",
        extensions={
            "timeout": {
                "connect": 60.0,
                "read": 0.5,
                "write": None,
                "pool": 7.0,
            },
        },
    )

    with pytest.raises(_StopSyncDispatch):
        transport.handle_request(request)

    extensions = observed["extensions"]
    assert extensions["timeout"] == {
        "connect": 2.0,
        "read": 0.5,
        "write": 4.0,
        "pool": 1.0,
    }
    assert extensions["sni_hostname"] == "api.example.com"
    transport.close()


@pytest.mark.asyncio
async def test_async_transport_binds_timeout_ceilings_before_pool_dispatch() -> None:
    """Pass only policy-bounded timeout metadata into asynchronous HTTPCore."""
    observed: dict[str, object] = {}

    class CapturingPool:
        """Capture one asynchronous core request without network I/O."""

        async def handle_async_request(self, request) -> None:
            """Record sanitized extensions and stop dispatch."""
            observed["extensions"] = request.extensions
            raise _StopAsyncDispatch

        async def aclose(self) -> None:
            """Close the inert asynchronous pool."""

    timeout_policy = EgressTimeoutPolicy(
        connect_timeout_seconds=2,
        read_timeout_seconds=3,
        write_timeout_seconds=4,
        pool_timeout_seconds=1,
    )
    policy = EgressPolicy.from_hosts(
        "api.example.com",
        request_timeout_policy=timeout_policy,
    )
    transport = async_transport_module._PinnedEgressAsyncTransport(
        _validated_result(),
        policy,
    )
    await transport._pool.aclose()
    transport._pool = CapturingPool()  # type: ignore[assignment]
    request = httpx.Request(
        "POST",
        "https://api.example.com/v1/models",
        content=b"payload",
        extensions={
            "timeout": {
                "connect": 60.0,
                "read": 0.5,
                "write": None,
                "pool": 7.0,
            },
        },
    )

    with pytest.raises(_StopAsyncDispatch):
        await transport.handle_async_request(request)

    extensions = observed["extensions"]
    assert extensions["timeout"] == {
        "connect": 2.0,
        "read": 0.5,
        "write": 4.0,
        "pool": 1.0,
    }
    assert extensions["sni_hostname"] == "api.example.com"
    await transport.aclose()


def test_public_package_exports_timeout_policy() -> None:
    """Expose the timeout ceiling contract through the stable package surface."""
    package = import_module("egressweave")

    assert package.EgressTimeoutPolicy is EgressTimeoutPolicy
    assert "EgressTimeoutPolicy" in package.__all__
