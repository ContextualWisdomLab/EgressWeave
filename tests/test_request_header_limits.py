"""Security contracts for finite outbound request-header budgets."""

from __future__ import annotations

from collections.abc import AsyncIterator, Iterator

import httpx
import pytest

from egressweave import (
    EGRESS_NOT_ALLOWED,
    EgressNotAllowedError,
    EgressPolicy,
    build_egress_decision_evidence,
)
from egressweave.policy import (
    DEFAULT_MAX_REQUEST_HEADER_BYTES,
    DEFAULT_MAX_REQUEST_HEADER_FIELDS,
)
from egressweave.request_safety import _enforce_request_header_limits
from egressweave.sync_transport import _PinnedEgressTransport
from egressweave.transport import _PinnedEgressAsyncTransport
from egressweave.validation import _make_validated_egress_url


class _FailingCloseSyncStream(httpx.SyncByteStream):
    """Record cleanup and raise hostile text from synchronous close."""

    def __init__(self) -> None:
        """Initialize the closure marker."""
        self.closed = False

    def __iter__(self) -> Iterator[bytes]:
        """Yield one inert body chunk if dispatch is attempted."""
        yield b"body"

    def close(self) -> None:
        """Record closure and simulate untrusted cleanup failure."""
        self.closed = True
        raise RuntimeError("attacker-controlled request close failure")


class _FailingCloseAsyncStream(httpx.AsyncByteStream):
    """Record cleanup and raise hostile text from asynchronous close."""

    def __init__(self) -> None:
        """Initialize the asynchronous closure marker."""
        self.closed = False

    async def __aiter__(self) -> AsyncIterator[bytes]:
        """Yield one inert body chunk if dispatch is attempted."""
        yield b"body"

    async def aclose(self) -> None:
        """Record closure and simulate untrusted asynchronous cleanup failure."""
        self.closed = True
        raise RuntimeError("attacker-controlled request close failure")


class _UnexpectedSyncPool:
    """Fail if rejected synchronous metadata reaches pool dispatch."""

    def handle_request(self, request) -> None:
        """Reject unexpected synchronous dispatch."""
        raise AssertionError("request reached the synchronous pool")


class _UnexpectedAsyncPool:
    """Fail if rejected asynchronous metadata reaches pool dispatch."""

    async def handle_async_request(self, request) -> None:
        """Reject unexpected asynchronous dispatch."""
        raise AssertionError("request reached the asynchronous pool")


class _FailingHeaderIterator:
    """Raise untrusted text while request metadata is counted."""

    def __iter__(self):
        """Fail before yielding a complete header section."""
        raise RuntimeError("attacker-controlled header iterator failure")


def _validated_result():
    """Return signed validation state without DNS or network I/O."""
    return _make_validated_egress_url(
        "https://api.example.com",
        "api.example.com",
        443,
        ("93.184.216.34",),
    )


def _policy(
    *,
    max_request_header_fields=4,
    max_request_header_bytes=128,
) -> EgressPolicy:
    """Return one exact authority with deliberately small header budgets."""
    return EgressPolicy.from_hosts(
        "api.example.com",
        max_request_header_fields=max_request_header_fields,
        max_request_header_bytes=max_request_header_bytes,
        max_request_bytes=1024,
    )


def test_request_header_budgets_have_finite_defaults() -> None:
    """Protect every integration even when an operator omits configuration."""
    policy = EgressPolicy.from_hosts("api.example.com")

    assert policy.max_request_header_fields == DEFAULT_MAX_REQUEST_HEADER_FIELDS
    assert policy.max_request_header_bytes == DEFAULT_MAX_REQUEST_HEADER_BYTES
    assert DEFAULT_MAX_REQUEST_HEADER_FIELDS == 100
    assert DEFAULT_MAX_REQUEST_HEADER_BYTES == 64 * 1024


def test_request_header_budgets_accept_ascii_decimal_environment_text() -> None:
    """Normalize positive decimal strings through both public constructors."""
    host_policy = EgressPolicy.from_hosts(
        "api.example.com",
        max_request_header_fields="12",
        max_request_header_bytes="4096",
    )
    authority_policy = EgressPolicy.from_authorities(
        [("api.example.com", 443)],
        max_request_header_fields="13",
        max_request_header_bytes="8192",
    )

    assert host_policy.max_request_header_fields == 12
    assert host_policy.max_request_header_bytes == 4096
    assert authority_policy.max_request_header_fields == 13
    assert authority_policy.max_request_header_bytes == 8192


@pytest.mark.parametrize(
    ("field_name", "value", "error_type"),
    [
        ("max_request_header_fields", True, TypeError),
        ("max_request_header_fields", 1.5, TypeError),
        ("max_request_header_fields", object(), TypeError),
        ("max_request_header_fields", 0, ValueError),
        ("max_request_header_fields", -1, ValueError),
        ("max_request_header_fields", "", ValueError),
        ("max_request_header_fields", "+1", ValueError),
        ("max_request_header_fields", "１", ValueError),
        ("max_request_header_bytes", True, TypeError),
        ("max_request_header_bytes", 1.5, TypeError),
        ("max_request_header_bytes", object(), TypeError),
        ("max_request_header_bytes", 0, ValueError),
        ("max_request_header_bytes", -1, ValueError),
        ("max_request_header_bytes", "", ValueError),
        ("max_request_header_bytes", "1.5", ValueError),
        ("max_request_header_bytes", "１", ValueError),
    ],
)
def test_request_header_budgets_reject_ambiguous_or_unbounded_configuration(
    field_name: str,
    value: object,
    error_type: type[Exception],
) -> None:
    """Fail during trusted policy construction rather than disabling limits."""
    with pytest.raises(error_type, match=field_name):
        EgressPolicy.from_hosts(
            "api.example.com",
            **{field_name: value},  # type: ignore[arg-type]
        )


def test_request_header_limit_accepts_exact_field_and_byte_boundaries() -> None:
    """Allow final outbound fields whose count and name-value bytes equal caps."""
    _enforce_request_header_limits(
        ((b"a", b"123"), (b"b", b"456")),
        max_request_header_fields=2,
        max_request_header_bytes=8,
    )


def test_request_header_limit_rejects_field_fanout() -> None:
    """Reject an outbound request containing more separate fields than allowed."""
    with pytest.raises(
        EgressNotAllowedError,
        match=f"^{EGRESS_NOT_ALLOWED}$",
    ):
        _enforce_request_header_limits(
            ((b"x-one", b"1"), (b"x-two", b"2")),
            max_request_header_fields=1,
            max_request_header_bytes=1024,
        )


def test_request_header_limit_rejects_one_oversized_field() -> None:
    """Reject one large credential or tracing field before pool dispatch."""
    with pytest.raises(
        EgressNotAllowedError,
        match=f"^{EGRESS_NOT_ALLOWED}$",
    ):
        _enforce_request_header_limits(
            ((b"authorization", b"a" * 1024),),
            max_request_header_fields=10,
            max_request_header_bytes=512,
        )


@pytest.mark.parametrize(
    "headers",
    [
        (("x-text", b"value"),),
        ((b"x-text", "value"),),
        ((bytearray(b"x-text"), b"value"),),
        ((b"x-text", bytearray(b"value")),),
        _FailingHeaderIterator(),
    ],
)
def test_request_header_limit_masks_malformed_or_failing_metadata(headers) -> None:
    """Keep downstream type and iterator failures behind the generic boundary."""
    with pytest.raises(
        EgressNotAllowedError,
        match=f"^{EGRESS_NOT_ALLOWED}$",
    ) as error:
        _enforce_request_header_limits(
            headers,
            max_request_header_fields=10,
            max_request_header_bytes=1024,
        )

    assert error.value.__cause__ is None


def test_request_header_budgets_change_audit_policy_fingerprints() -> None:
    """Make outbound metadata-budget drift visible in decision evidence."""
    validated = _validated_result()
    smaller_fields = _policy(max_request_header_fields=3)
    larger_fields = _policy(max_request_header_fields=4)
    smaller_bytes = _policy(max_request_header_bytes=127)
    larger_bytes = _policy(max_request_header_bytes=128)

    field_evidence = [
        build_egress_decision_evidence(validated, policy=policy)
        for policy in (smaller_fields, larger_fields)
    ]
    byte_evidence = [
        build_egress_decision_evidence(validated, policy=policy)
        for policy in (smaller_bytes, larger_bytes)
    ]

    assert field_evidence[0].policy_fingerprint != field_evidence[1].policy_fingerprint
    assert (
        field_evidence[0].decision_fingerprint
        != field_evidence[1].decision_fingerprint
    )
    assert byte_evidence[0].policy_fingerprint != byte_evidence[1].policy_fingerprint
    assert (
        byte_evidence[0].decision_fingerprint
        != byte_evidence[1].decision_fingerprint
    )


def test_sync_transport_rejects_final_header_fanout_and_closes_request_stream() -> None:
    """Count rewritten Host and Accept-Encoding fields before synchronous dispatch."""
    source = _FailingCloseSyncStream()
    transport = object.__new__(_PinnedEgressTransport)
    transport._validated = _validated_result()
    transport._policy = _policy(max_request_header_fields=2)
    transport._pool = _UnexpectedSyncPool()
    request = httpx.Request(
        "POST",
        "https://api.example.com/v1/items",
        headers=((b"x-one", b"1"),),
        stream=source,
    )

    with pytest.raises(
        EgressNotAllowedError,
        match=f"^{EGRESS_NOT_ALLOWED}$",
    ) as error:
        transport.handle_request(request)

    assert source.closed is True
    assert error.value.__cause__ is None


@pytest.mark.asyncio
async def test_async_transport_rejects_final_header_bytes_and_closes_request_stream() -> None:
    """Count final rewritten bytes and mask asynchronous cleanup failures."""
    source = _FailingCloseAsyncStream()
    transport = object.__new__(_PinnedEgressAsyncTransport)
    transport._validated = _validated_result()
    transport._policy = _policy(max_request_header_bytes=64)
    transport._pool = _UnexpectedAsyncPool()
    request = httpx.Request(
        "POST",
        "https://api.example.com/v1/items",
        headers=((b"x-trace", b"a" * 64),),
        stream=source,
    )

    with pytest.raises(
        EgressNotAllowedError,
        match=f"^{EGRESS_NOT_ALLOWED}$",
    ) as error:
        await transport.handle_async_request(request)

    assert source.closed is True
    assert error.value.__cause__ is None
