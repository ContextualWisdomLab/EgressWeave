"""Regression coverage for fail-closed outbound response-body limits."""

import gzip
from types import SimpleNamespace

import httpx
import pytest

from egressweave import EgressNotAllowedError, EgressPolicy
from egressweave.policy import DEFAULT_MAX_RESPONSE_BYTES
from egressweave.response_safety import (
    _BoundedAsyncResponseStream,
    _BoundedSyncResponseStream,
    _enforce_declared_response_size,
)
from egressweave.sync_transport import _PinnedEgressTransport
from egressweave.transport import _PinnedEgressAsyncTransport
from egressweave.validation import _make_validated_egress_url


class _ClosableSyncStream(httpx.SyncByteStream):
    """Expose deterministic chunks and record connection-release behavior."""

    def __init__(self, chunks: tuple[bytes, ...]) -> None:
        self._chunks = chunks
        self.closed = False

    def __iter__(self):
        """Yield the configured response chunks."""
        yield from self._chunks

    def close(self) -> None:
        """Record that the response stream released its connection."""
        self.closed = True


class _ClosableAsyncStream(httpx.AsyncByteStream):
    """Expose deterministic async chunks and record connection release."""

    def __init__(self, chunks: tuple[bytes, ...]) -> None:
        self._chunks = chunks
        self.closed = False

    async def __aiter__(self):
        """Yield the configured response chunks asynchronously."""
        for chunk in self._chunks:
            yield chunk

    async def aclose(self) -> None:
        """Record that the response stream released its connection."""
        self.closed = True


class _SyncPool:
    """Return one offline HTTPCore-shaped response."""

    def __init__(self, headers, stream) -> None:
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
    """Return one offline asynchronous HTTPCore-shaped response."""

    def __init__(self, headers, stream) -> None:
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
    """Return factory-issued validation state without performing DNS I/O."""
    return _make_validated_egress_url(
        "https://api.openai.com",
        "api.openai.com",
        443,
        ("93.184.216.34",),
    )


def _policy(max_response_bytes=4) -> EgressPolicy:
    """Return a policy with a deliberately small response budget."""
    return EgressPolicy.from_hosts(
        "api.openai.com", max_response_bytes=max_response_bytes
    )


def _sync_transport(
    headers, stream, *, max_response_bytes=4
) -> _PinnedEgressTransport:
    """Build an offline synchronous pinned transport double."""
    transport = object.__new__(_PinnedEgressTransport)
    transport._validated = _validated_result()
    transport._policy = _policy(max_response_bytes)
    transport._pool = _SyncPool(headers, stream)
    return transport


def _async_transport(
    headers, stream, *, max_response_bytes=4
) -> _PinnedEgressAsyncTransport:
    """Build an offline asynchronous pinned transport double."""
    transport = object.__new__(_PinnedEgressAsyncTransport)
    transport._validated = _validated_result()
    transport._policy = _policy(max_response_bytes)
    transport._pool = _AsyncPool(headers, stream)
    return transport


def _request() -> httpx.Request:
    """Return one request matching the validated authority."""
    return httpx.Request("GET", "https://api.openai.com/v1/models")


def _gzip_headers(encoded_body: bytes) -> tuple[tuple[bytes, bytes], ...]:
    """Return response headers for one deterministic gzip-encoded body."""
    return (
        (b"Content-Encoding", b"gzip"),
        (b"Content-Length", str(len(encoded_body)).encode("ascii")),
    )


def test_response_budget_has_a_secure_finite_default() -> None:
    """Bound response consumption even when an operator omits configuration."""
    policy = EgressPolicy.from_hosts("api.openai.com")

    assert policy.max_response_bytes == DEFAULT_MAX_RESPONSE_BYTES
    assert DEFAULT_MAX_RESPONSE_BYTES == 16 * 1024 * 1024


def test_response_budget_accepts_decimal_environment_text() -> None:
    """Normalize a positive decimal string for environment-variable use."""
    assert _policy("4096").max_response_bytes == 4096


@pytest.mark.parametrize("invalid_value", [True, 1.5, object()])
def test_response_budget_rejects_non_integer_types(invalid_value) -> None:
    """Reject ambiguous values that could silently disable resource bounds."""
    with pytest.raises(TypeError, match="max_response_bytes must be"):
        _policy(invalid_value)


@pytest.mark.parametrize("invalid_value", ["", "1.5", "１２", "-1"])
def test_response_budget_rejects_non_decimal_text(invalid_value: str) -> None:
    """Reject empty, signed, non-ASCII, or fractional text configuration."""
    with pytest.raises(ValueError, match="positive decimal byte count"):
        _policy(invalid_value)


@pytest.mark.parametrize("invalid_value", [0, -1])
def test_response_budget_rejects_non_positive_integers(invalid_value: int) -> None:
    """Reject zero or negative response budgets."""
    with pytest.raises(ValueError, match="greater than zero"):
        _policy(invalid_value)


def test_declared_response_size_accepts_absent_or_in_budget_length() -> None:
    """Allow unrelated metadata, unknown lengths, and one in-budget length."""
    _enforce_declared_response_size("GET", 200, (), 4)
    _enforce_declared_response_size("GET", 200, ((b"X-Trace", b"one"),), 4)
    _enforce_declared_response_size(
        "GET", 200, ((b"Content-Length", b"4"),), 4
    )


@pytest.mark.parametrize(
    "headers",
    [
        ((b"Content-Length", b"5"),),
        ((b"Content-Length", b"4"), (b"content-length", b"4")),
        ((b"Content-Length", b""),),
        ((b"Content-Length", b"4, 4"),),
        ((b"Content-Length", b"+4"),),
    ],
)
def test_declared_response_size_rejects_unsafe_length(headers) -> None:
    """Reject oversized, duplicated, or malformed response length metadata."""
    with pytest.raises(EgressNotAllowedError, match="^egress URL is not allowed$"):
        _enforce_declared_response_size("GET", 200, headers, 4)


@pytest.mark.parametrize(
    ("method", "status_code"),
    [("HEAD", 200), ("GET", 101), ("GET", 204), ("GET", 304)],
)
def test_declared_response_size_ignores_bodyless_response_metadata(
    method: str, status_code: int
) -> None:
    """Do not reject representation metadata on responses that carry no body."""
    _enforce_declared_response_size(
        method, status_code, ((b"Content-Length", b"999999999999"),), 4
    )


def test_sync_stream_allows_exact_budget_and_manual_close() -> None:
    """Yield exactly the configured raw-byte budget and preserve close semantics."""
    source = _ClosableSyncStream((b"ab", b"cd"))
    stream = _BoundedSyncResponseStream(source, 4)

    assert b"".join(stream) == b"abcd"
    stream.close()
    assert source.closed is True


def test_sync_stream_rejects_overrun_and_closes_source() -> None:
    """Stop before exposing the raw chunk that would exceed the budget."""
    source = _ClosableSyncStream((b"ab", b"cde"))
    stream = _BoundedSyncResponseStream(source, 4)

    iterator = iter(stream)
    assert next(iterator) == b"ab"
    with pytest.raises(EgressNotAllowedError, match="^egress URL is not allowed$"):
        next(iterator)
    assert source.closed is True


async def test_async_stream_allows_exact_budget_and_manual_close() -> None:
    """Yield exactly the async raw-byte budget and preserve close semantics."""
    source = _ClosableAsyncStream((b"ab", b"cd"))
    stream = _BoundedAsyncResponseStream(source, 4)

    assert b"".join([chunk async for chunk in stream]) == b"abcd"
    await stream.aclose()
    assert source.closed is True


async def test_async_stream_rejects_overrun_and_closes_source() -> None:
    """Stop async consumption before exposing an over-budget raw chunk."""
    source = _ClosableAsyncStream((b"ab", b"cde"))
    stream = _BoundedAsyncResponseStream(source, 4)

    iterator = stream.__aiter__()
    assert await anext(iterator) == b"ab"
    with pytest.raises(EgressNotAllowedError, match="^egress URL is not allowed$"):
        await anext(iterator)
    assert source.closed is True


def test_sync_transport_rejects_oversized_declared_body_and_closes() -> None:
    """Reject an oversized Content-Length before returning a response object."""
    source = _ClosableSyncStream((b"abcde",))

    with pytest.raises(EgressNotAllowedError, match="^egress URL is not allowed$"):
        _sync_transport(((b"Content-Length", b"5"),), source).handle_request(
            _request()
        )

    assert source.closed is True


def test_sync_transport_bounds_unknown_length_body_during_read() -> None:
    """Enforce the raw and decoded budgets for an unknown-size body."""
    source = _ClosableSyncStream((b"ab", b"cde"))
    response = _sync_transport((), source).handle_request(_request())

    with pytest.raises(EgressNotAllowedError, match="^egress URL is not allowed$"):
        response.read()

    assert source.closed is True


def test_sync_transport_bounds_gzip_decoded_body() -> None:
    """Reject a small gzip transfer whose decoded output exceeds the budget."""
    encoded_body = gzip.compress(b"x" * 1000)
    assert len(encoded_body) < 100
    source = _ClosableSyncStream((encoded_body,))
    response = _sync_transport(
        _gzip_headers(encoded_body), source, max_response_bytes=100
    ).handle_request(_request())

    with pytest.raises(EgressNotAllowedError, match="^egress URL is not allowed$"):
        response.read()

    assert source.closed is True


async def test_async_transport_rejects_oversized_declared_body_and_closes() -> None:
    """Reject an oversized async Content-Length and release its stream."""
    source = _ClosableAsyncStream((b"abcde",))

    with pytest.raises(EgressNotAllowedError, match="^egress URL is not allowed$"):
        await _async_transport(
            ((b"Content-Length", b"5"),), source
        ).handle_async_request(_request())

    assert source.closed is True


async def test_async_transport_bounds_unknown_length_body_during_read() -> None:
    """Enforce raw and decoded budgets for an async unknown-size body."""
    source = _ClosableAsyncStream((b"ab", b"cde"))
    response = await _async_transport((), source).handle_async_request(_request())

    with pytest.raises(EgressNotAllowedError, match="^egress URL is not allowed$"):
        await response.aread()

    assert source.closed is True


async def test_async_transport_bounds_gzip_decoded_body() -> None:
    """Reject async gzip amplification beyond the decoded response budget."""
    encoded_body = gzip.compress(b"x" * 1000)
    assert len(encoded_body) < 100
    source = _ClosableAsyncStream((encoded_body,))
    response = await _async_transport(
        _gzip_headers(encoded_body), source, max_response_bytes=100
    ).handle_async_request(_request())

    with pytest.raises(EgressNotAllowedError, match="^egress URL is not allowed$"):
        await response.aread()

    assert source.closed is True
