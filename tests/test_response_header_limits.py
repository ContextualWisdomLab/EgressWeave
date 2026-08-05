"""Security contracts for finite response-header field and byte budgets."""

from __future__ import annotations

from types import SimpleNamespace

import httpx
import pytest

from egressweave import (
    EGRESS_NOT_ALLOWED,
    EgressNotAllowedError,
    EgressPolicy,
    build_egress_decision_evidence,
)
from egressweave.policy import (
    DEFAULT_MAX_RESPONSE_HEADER_BYTES,
    DEFAULT_MAX_RESPONSE_HEADER_FIELDS,
)
from egressweave.response_safety import _enforce_response_header_limits
from egressweave.sync_transport import _PinnedEgressTransport
from egressweave.transport import _PinnedEgressAsyncTransport
from egressweave.validation import _make_validated_egress_url


class _ClosableSyncStream(httpx.SyncByteStream):
    """Record whether a rejected synchronous response releases its connection."""

    def __init__(self) -> None:
        """Initialize the source closure marker."""
        self.closed = False

    def __iter__(self):
        """Yield one inert body chunk if a response is ever exposed."""
        yield b"body"

    def close(self) -> None:
        """Record synchronous source closure."""
        self.closed = True


class _ClosableAsyncStream(httpx.AsyncByteStream):
    """Record whether a rejected asynchronous response releases its connection."""

    def __init__(self) -> None:
        """Initialize the asynchronous source closure marker."""
        self.closed = False

    async def __aiter__(self):
        """Yield one inert body chunk if a response is ever exposed."""
        yield b"body"

    async def aclose(self) -> None:
        """Record asynchronous source closure."""
        self.closed = True


class _SyncPool:
    """Return one offline HTTPCore-shaped synchronous response."""

    def __init__(self, headers, stream) -> None:
        """Store deterministic response metadata and body stream."""
        self._headers = headers
        self._stream = stream

    def handle_request(self, request):
        """Return the configured response without network I/O."""
        return SimpleNamespace(
            status=200,
            headers=self._headers,
            stream=self._stream,
            extensions={},
        )


class _AsyncPool:
    """Return one offline HTTPCore-shaped asynchronous response."""

    def __init__(self, headers, stream) -> None:
        """Store deterministic asynchronous response state."""
        self._headers = headers
        self._stream = stream

    async def handle_async_request(self, request):
        """Return the configured response without network I/O."""
        return SimpleNamespace(
            status=200,
            headers=self._headers,
            stream=self._stream,
            extensions={},
        )


def _validated_result():
    """Return signed validation state without performing DNS I/O."""
    return _make_validated_egress_url(
        "https://api.example.com",
        "api.example.com",
        443,
        ("93.184.216.34",),
    )


def _policy(
    *,
    max_response_header_fields=4,
    max_response_header_bytes=32,
) -> EgressPolicy:
    """Return one policy with deliberately small response-header budgets."""
    return EgressPolicy.from_hosts(
        "api.example.com",
        max_response_header_fields=max_response_header_fields,
        max_response_header_bytes=max_response_header_bytes,
        max_response_bytes=1024,
    )


def _request() -> httpx.Request:
    """Return one request matching the signed authority."""
    return httpx.Request("GET", "https://api.example.com/v1/models")


def test_response_header_budgets_have_finite_defaults() -> None:
    """Protect every integration even when an operator omits configuration."""
    policy = EgressPolicy.from_hosts("api.example.com")

    assert policy.max_response_header_fields == DEFAULT_MAX_RESPONSE_HEADER_FIELDS
    assert policy.max_response_header_bytes == DEFAULT_MAX_RESPONSE_HEADER_BYTES
    assert DEFAULT_MAX_RESPONSE_HEADER_FIELDS == 100
    assert DEFAULT_MAX_RESPONSE_HEADER_BYTES == 64 * 1024


def test_response_header_budgets_accept_ascii_decimal_environment_text() -> None:
    """Normalize positive decimal strings through both public constructors."""
    host_policy = EgressPolicy.from_hosts(
        "api.example.com",
        max_response_header_fields="12",
        max_response_header_bytes="4096",
    )
    authority_policy = EgressPolicy.from_authorities(
        [("api.example.com", 443)],
        max_response_header_fields="13",
        max_response_header_bytes="8192",
    )

    assert host_policy.max_response_header_fields == 12
    assert host_policy.max_response_header_bytes == 4096
    assert authority_policy.max_response_header_fields == 13
    assert authority_policy.max_response_header_bytes == 8192


@pytest.mark.parametrize(
    ("field_name", "value", "error_type"),
    [
        ("max_response_header_fields", True, TypeError),
        ("max_response_header_fields", 1.5, TypeError),
        ("max_response_header_fields", object(), TypeError),
        ("max_response_header_fields", 0, ValueError),
        ("max_response_header_fields", -1, ValueError),
        ("max_response_header_fields", "", ValueError),
        ("max_response_header_fields", "+1", ValueError),
        ("max_response_header_fields", "１", ValueError),
        ("max_response_header_bytes", True, TypeError),
        ("max_response_header_bytes", 1.5, TypeError),
        ("max_response_header_bytes", object(), TypeError),
        ("max_response_header_bytes", 0, ValueError),
        ("max_response_header_bytes", -1, ValueError),
        ("max_response_header_bytes", "", ValueError),
        ("max_response_header_bytes", "1.5", ValueError),
        ("max_response_header_bytes", "１", ValueError),
    ],
)
def test_response_header_budgets_reject_ambiguous_or_unbounded_configuration(
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


def test_response_header_limit_accepts_exact_field_and_byte_boundaries() -> None:
    """Allow a response whose field count and name-value octets equal the caps."""
    _enforce_response_header_limits(
        ((b"a", b"123"), (b"b", b"456")),
        max_response_header_fields=2,
        max_response_header_bytes=8,
    )


def test_response_header_limit_rejects_realistic_cookie_field_fanout() -> None:
    """Reject a compromised API returning more separate Set-Cookie fields than allowed."""
    headers = tuple(
        (b"set-cookie", f"session_{index}=value; Secure".encode("ascii"))
        for index in range(5)
    )

    with pytest.raises(
        EgressNotAllowedError,
        match=f"^{EGRESS_NOT_ALLOWED}$",
    ):
        _enforce_response_header_limits(
            headers,
            max_response_header_fields=4,
            max_response_header_bytes=4096,
        )


def test_response_header_limit_rejects_one_oversized_trace_field() -> None:
    """Reject one large diagnostic field before it becomes caller-visible."""
    with pytest.raises(
        EgressNotAllowedError,
        match=f"^{EGRESS_NOT_ALLOWED}$",
    ):
        _enforce_response_header_limits(
            ((b"x-trace", b"a" * 1024),),
            max_response_header_fields=10,
            max_response_header_bytes=512,
        )


@pytest.mark.parametrize(
    "headers",
    [
        (("x-text", b"value"),),
        ((b"x-text", "value"),),
        ((bytearray(b"x-text"), b"value"),),
        ((b"x-text", bytearray(b"value")),),
    ],
)
def test_response_header_limit_rejects_non_byte_metadata_generically(headers) -> None:
    """Fail closed if a downstream protocol object violates the byte-header contract."""
    with pytest.raises(
        EgressNotAllowedError,
        match=f"^{EGRESS_NOT_ALLOWED}$",
    ) as error:
        _enforce_response_header_limits(
            headers,
            max_response_header_fields=10,
            max_response_header_bytes=1024,
        )

    assert error.value.__cause__ is None


def test_response_header_budgets_change_audit_policy_fingerprints() -> None:
    """Make field-count and byte-budget drift visible in decision evidence."""
    validated = _validated_result()
    smaller_fields = _policy(max_response_header_fields=3)
    larger_fields = _policy(max_response_header_fields=4)
    smaller_bytes = _policy(max_response_header_bytes=31)
    larger_bytes = _policy(max_response_header_bytes=32)

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


def test_sync_transport_rejects_header_fanout_and_closes_response_stream() -> None:
    """Close an over-field-count response before returning an HTTPX response."""
    source = _ClosableSyncStream()
    transport = object.__new__(_PinnedEgressTransport)
    transport._validated = _validated_result()
    transport._policy = _policy(max_response_header_fields=1)
    transport._pool = _SyncPool(((b"x-one", b"1"), (b"x-two", b"2")), source)

    with pytest.raises(
        EgressNotAllowedError,
        match=f"^{EGRESS_NOT_ALLOWED}$",
    ):
        transport.handle_request(_request())

    assert source.closed is True


@pytest.mark.asyncio
async def test_async_transport_rejects_header_bytes_and_closes_response_stream() -> None:
    """Close an over-byte-budget response before returning an HTTPX response."""
    source = _ClosableAsyncStream()
    transport = object.__new__(_PinnedEgressAsyncTransport)
    transport._validated = _validated_result()
    transport._policy = _policy(max_response_header_bytes=4)
    transport._pool = _AsyncPool(((b"x", b"1234"),), source)

    with pytest.raises(
        EgressNotAllowedError,
        match=f"^{EGRESS_NOT_ALLOWED}$",
    ):
        await transport.handle_async_request(_request())

    assert source.closed is True
