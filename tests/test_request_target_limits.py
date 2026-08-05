"""Security contracts for finite outbound request-target budgets."""

from __future__ import annotations

from collections.abc import AsyncIterator, Iterator

import httpx
import pytest

from egressweave import (
    EGRESS_NOT_ALLOWED,
    EgressNotAllowedError,
    EgressPolicy,
    EgressTimeoutPolicy,
    build_egress_decision_evidence,
)
from egressweave import request_safety as request_safety_module
from egressweave._policy_normalization import (
    DEFAULT_MAX_REQUEST_TARGET_BYTES,
    _normalize_max_request_target_bytes,
)
from egressweave.sync_transport import _PinnedEgressTransport
from egressweave.transport import _PinnedEgressAsyncTransport
from egressweave.validation import _make_validated_egress_url


class _StopSyncDispatch(RuntimeError):
    """Stop a synchronous transport after capturing its exact core target."""


class _StopAsyncDispatch(RuntimeError):
    """Stop an asynchronous transport after capturing its exact core target."""


class _FailingCloseSyncStream(httpx.SyncByteStream):
    """Record synchronous cleanup and raise attacker-controlled failure text."""

    def __init__(self) -> None:
        """Initialize the closure marker."""
        self.closed = False

    def __iter__(self) -> Iterator[bytes]:
        """Yield one inert body chunk if dispatch is attempted unexpectedly."""
        yield b"body"

    def close(self) -> None:
        """Record closure and simulate a hostile cleanup implementation."""
        self.closed = True
        raise RuntimeError("attacker-controlled request close failure")


class _FailingCloseAsyncStream(httpx.AsyncByteStream):
    """Record asynchronous cleanup and raise attacker-controlled failure text."""

    def __init__(self) -> None:
        """Initialize the asynchronous closure marker."""
        self.closed = False

    async def __aiter__(self) -> AsyncIterator[bytes]:
        """Yield one inert body chunk if dispatch is attempted unexpectedly."""
        yield b"body"

    async def aclose(self) -> None:
        """Record closure and simulate a hostile asynchronous cleanup method."""
        self.closed = True
        raise RuntimeError("attacker-controlled request close failure")


class _UnexpectedSyncPool:
    """Fail if a rejected synchronous target reaches pool dispatch."""

    def handle_request(self, request) -> None:
        """Reject unexpected synchronous dispatch."""
        raise AssertionError("request reached the synchronous pool")


class _UnexpectedAsyncPool:
    """Fail if a rejected asynchronous target reaches pool dispatch."""

    async def handle_async_request(self, request) -> None:
        """Reject unexpected asynchronous dispatch."""
        raise AssertionError("request reached the asynchronous pool")


class _CapturingSyncPool:
    """Capture the exact synchronous HTTPCore target without network I/O."""

    def __init__(self, observed: dict[str, object]) -> None:
        """Store the shared observation mapping."""
        self._observed = observed

    def handle_request(self, request) -> None:
        """Record the target and stop before response handling."""
        self._observed["target"] = request.url.target
        raise _StopSyncDispatch


class _CapturingAsyncPool:
    """Capture the exact asynchronous HTTPCore target without network I/O."""

    def __init__(self, observed: dict[str, object]) -> None:
        """Store the shared observation mapping."""
        self._observed = observed

    async def handle_async_request(self, request) -> None:
        """Record the target and stop before response handling."""
        self._observed["target"] = request.url.target
        raise _StopAsyncDispatch


class _HostileBytes(bytes):
    """Represent a bytes subclass that must not cross the exact-type boundary."""


def _validated_result():
    """Return signed validation state without DNS or network I/O."""
    return _make_validated_egress_url(
        "https://api.example.com",
        "api.example.com",
        443,
        ("93.184.216.34",),
    )


def _policy(*, max_request_target_bytes=32) -> EgressPolicy:
    """Return one exact authority with a deliberately small target budget."""
    return EgressPolicy.from_hosts(
        "api.example.com",
        max_request_target_bytes=max_request_target_bytes,
        max_request_bytes=1024,
    )


def test_request_target_budget_has_finite_default() -> None:
    """Protect integrations even when operators omit target configuration."""
    policy = EgressPolicy.from_hosts("api.example.com")

    assert DEFAULT_MAX_REQUEST_TARGET_BYTES == 8 * 1024
    assert policy.max_request_target_bytes == DEFAULT_MAX_REQUEST_TARGET_BYTES


@pytest.mark.parametrize("value", [1, 8192, "1", "8192"])
def test_request_target_budget_normalizes_positive_values(value: int | str) -> None:
    """Accept positive integers and ASCII decimal environment text."""
    assert _normalize_max_request_target_bytes(value) == int(value)


def test_public_constructors_normalize_request_target_budget() -> None:
    """Expose identical request-target configuration through both factories."""
    host_policy = EgressPolicy.from_hosts(
        "api.example.com",
        max_request_target_bytes="8192",
    )
    authority_policy = EgressPolicy.from_authorities(
        [("api.example.com", 443)],
        max_request_target_bytes="4096",
    )

    assert host_policy.max_request_target_bytes == 8192
    assert authority_policy.max_request_target_bytes == 4096


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
    """Fail during trusted policy construction instead of disabling the limit."""
    with pytest.raises(error_type, match="max_request_target_bytes"):
        EgressPolicy.from_hosts(
            "api.example.com",
            max_request_target_bytes=value,  # type: ignore[arg-type]
        )


def test_new_target_limit_preserves_existing_positional_policy_order() -> None:
    """Append the field without reinterpreting any prior positional argument."""
    timeout_policy = EgressTimeoutPolicy()
    policy = EgressPolicy(
        frozenset({"api.example.com"}),
        False,
        5.0,
        frozenset({443}),
        frozenset({"GET"}),
        2048,
        None,
        1024,
        16,
        timeout_policy,
        101,
        65536,
        102,
        65537,
    )

    assert policy.max_response_bytes == 2048
    assert policy.max_request_bytes == 1024
    assert policy.max_resolved_addresses == 16
    assert policy.request_timeout_policy is timeout_policy
    assert policy.max_response_header_fields == 101
    assert policy.max_response_header_bytes == 65536
    assert policy.max_request_header_fields == 102
    assert policy.max_request_header_bytes == 65537
    assert policy.max_request_target_bytes == DEFAULT_MAX_REQUEST_TARGET_BYTES


def test_request_target_limit_accepts_the_exact_byte_boundary() -> None:
    """Return an exact byte target unchanged when it equals the configured cap."""
    target = b"/" + b"a" * 7

    assert request_safety_module._enforce_request_target_limit(target, 8) == target


def test_request_target_limit_rejects_the_first_byte_over_budget() -> None:
    """Reject one excess path or query byte through the generic denial boundary."""
    with pytest.raises(
        EgressNotAllowedError,
        match=f"^{EGRESS_NOT_ALLOWED}$",
    ) as error:
        request_safety_module._enforce_request_target_limit(b"/" + b"a" * 8, 8)

    assert error.value.__cause__ is None
    assert error.value.__context__ is None


@pytest.mark.parametrize(
    "target",
    [
        "/path",
        bytearray(b"/path"),
        memoryview(b"/path"),
        _HostileBytes(b"/path"),
    ],
)
def test_request_target_limit_rejects_non_exact_byte_values(target: object) -> None:
    """Refuse alternate buffer and subclass protocols before downstream parsing."""
    with pytest.raises(
        EgressNotAllowedError,
        match=f"^{EGRESS_NOT_ALLOWED}$",
    ) as error:
        request_safety_module._enforce_request_target_limit(target, 8192)

    assert error.value.__cause__ is None
    assert error.value.__context__ is None


def test_httpx_raw_path_preserves_percent_encoded_path_and_query_bytes() -> None:
    """Count the exact encoded origin-form target that HTTPX will delegate."""
    request = httpx.Request(
        "GET",
        "https://api.example.com/a b?q=ü",
    )
    expected_target = b"/a%20b?q=%C3%BC"

    assert request.url.raw_path == expected_target
    assert request_safety_module._enforce_request_target_limit(
        request.url.raw_path,
        len(expected_target),
    ) == expected_target


def test_request_target_budget_changes_audit_policy_fingerprints() -> None:
    """Make target-budget drift visible without recording request paths."""
    validated = _validated_result()
    smaller = _policy(max_request_target_bytes=31)
    larger = _policy(max_request_target_bytes=32)

    smaller_evidence = build_egress_decision_evidence(validated, policy=smaller)
    larger_evidence = build_egress_decision_evidence(validated, policy=larger)

    assert smaller_evidence.policy_fingerprint != larger_evidence.policy_fingerprint
    assert smaller_evidence.decision_fingerprint != larger_evidence.decision_fingerprint


def test_sync_transport_forwards_the_exact_encoded_target() -> None:
    """Delegate the unchanged encoded path and query to synchronous HTTPCore."""
    observed: dict[str, object] = {}
    transport = object.__new__(_PinnedEgressTransport)
    transport._validated = _validated_result()
    transport._policy = _policy(max_request_target_bytes=64)
    transport._pool = _CapturingSyncPool(observed)
    request = httpx.Request(
        "GET",
        "https://api.example.com/a b?q=ü",
        content=b"",
    )

    with pytest.raises(_StopSyncDispatch):
        transport.handle_request(request)

    assert observed["target"] == b"/a%20b?q=%C3%BC"


@pytest.mark.asyncio
async def test_async_transport_forwards_the_exact_encoded_target() -> None:
    """Delegate the unchanged encoded path and query to asynchronous HTTPCore."""
    observed: dict[str, object] = {}
    transport = object.__new__(_PinnedEgressAsyncTransport)
    transport._validated = _validated_result()
    transport._policy = _policy(max_request_target_bytes=64)
    transport._pool = _CapturingAsyncPool(observed)
    request = httpx.Request(
        "GET",
        "https://api.example.com/a b?q=ü",
        content=b"",
    )

    with pytest.raises(_StopAsyncDispatch):
        await transport.handle_async_request(request)

    assert observed["target"] == b"/a%20b?q=%C3%BC"


def test_sync_transport_rejects_oversized_target_and_closes_request_stream() -> None:
    """Deny before synchronous pool dispatch and mask hostile cleanup failures."""
    source = _FailingCloseSyncStream()
    transport = object.__new__(_PinnedEgressTransport)
    transport._validated = _validated_result()
    transport._policy = _policy(max_request_target_bytes=8)
    transport._pool = _UnexpectedSyncPool()
    request = httpx.Request(
        "POST",
        "https://api.example.com/12345678",
        stream=source,
    )

    with pytest.raises(
        EgressNotAllowedError,
        match=f"^{EGRESS_NOT_ALLOWED}$",
    ) as error:
        transport.handle_request(request)

    assert source.closed is True
    assert error.value.__cause__ is None
    assert error.value.__context__ is None


@pytest.mark.asyncio
async def test_async_transport_rejects_oversized_target_and_closes_request_stream() -> None:
    """Deny before async pool dispatch and mask hostile cleanup failures."""
    source = _FailingCloseAsyncStream()
    transport = object.__new__(_PinnedEgressAsyncTransport)
    transport._validated = _validated_result()
    transport._policy = _policy(max_request_target_bytes=8)
    transport._pool = _UnexpectedAsyncPool()
    request = httpx.Request(
        "POST",
        "https://api.example.com/12345678",
        stream=source,
    )

    with pytest.raises(
        EgressNotAllowedError,
        match=f"^{EGRESS_NOT_ALLOWED}$",
    ) as error:
        await transport.handle_async_request(request)

    assert source.closed is True
    assert error.value.__cause__ is None
    assert error.value.__context__ is None
