"""Regression coverage for fail-closed outbound request-body limits."""

from __future__ import annotations

from collections.abc import AsyncIterator, Iterator
from types import SimpleNamespace

import httpx
import pytest
from egressweave.request_body_safety import (
    _BoundedAsyncRequestStream,
    _BoundedSyncRequestStream,
    _enforce_declared_request_size,
)

from egressweave import EgressNotAllowedError, EgressPolicy
from egressweave.sync_transport import _PinnedEgressTransport
from egressweave.transport import _PinnedEgressAsyncTransport
from egressweave.validation import _make_validated_egress_url


class _ClosableSyncRequestStream(httpx.SyncByteStream):
    """Yield deterministic request chunks and record source closure."""

    def __init__(
        self,
        chunks: tuple[bytes, ...],
        *,
        close_error: Exception | None = None,
    ) -> None:
        """Store request chunks, closure state, and an optional close failure."""
        self._chunks = chunks
        self._close_error = close_error
        self.closed = False

    def __iter__(self) -> Iterator[bytes]:
        """Yield the configured request chunks."""
        yield from self._chunks

    def close(self) -> None:
        """Record closure and optionally simulate an untrusted source failure."""
        self.closed = True
        if self._close_error is not None:
            raise self._close_error


class _ClosableAsyncRequestStream(httpx.AsyncByteStream):
    """Yield deterministic asynchronous request chunks and record closure."""

    def __init__(
        self,
        chunks: tuple[bytes, ...],
        *,
        close_error: Exception | None = None,
    ) -> None:
        """Store request chunks, closure state, and an optional close failure."""
        self._chunks = chunks
        self._close_error = close_error
        self.closed = False

    async def __aiter__(self) -> AsyncIterator[bytes]:
        """Yield the configured request chunks asynchronously."""
        for chunk in self._chunks:
            yield chunk

    async def aclose(self) -> None:
        """Record closure and optionally simulate an untrusted source failure."""
        self.closed = True
        if self._close_error is not None:
            raise self._close_error


class _EmptySyncResponseStream(httpx.SyncByteStream):
    """Provide one bodyless offline synchronous response stream."""

    def __iter__(self) -> Iterator[bytes]:
        """Yield no response chunks."""
        return iter(())

    def close(self) -> None:
        """Close the stateless response stream."""


class _EmptyAsyncResponseStream(httpx.AsyncByteStream):
    """Provide one bodyless offline asynchronous response stream."""

    async def __aiter__(self) -> AsyncIterator[bytes]:
        """Yield no response chunks."""
        if False:  # pragma: no cover - required to form an async generator
            yield b""

    async def aclose(self) -> None:
        """Close the stateless asynchronous response stream."""


class _SyncRequestPool:
    """Consume one outbound request stream without network I/O."""

    def __init__(self) -> None:
        """Initialize request-observation state."""
        self.called = False
        self.body: bytes | None = None

    def handle_request(self, request) -> SimpleNamespace:
        """Consume the request and return an HTTP 204 response."""
        self.called = True
        try:
            self.body = b"".join(request.stream)
        finally:
            request.stream.close()
        return SimpleNamespace(
            status=204,
            headers=(),
            stream=_EmptySyncResponseStream(),
            extensions={},
        )


class _AsyncRequestPool:
    """Consume one outbound asynchronous request stream without network I/O."""

    def __init__(self) -> None:
        """Initialize request-observation state."""
        self.called = False
        self.body: bytes | None = None

    async def handle_async_request(self, request) -> SimpleNamespace:
        """Consume the request and return an HTTP 204 response."""
        self.called = True
        try:
            self.body = b"".join([chunk async for chunk in request.stream])
        finally:
            await request.stream.aclose()
        return SimpleNamespace(
            status=204,
            headers=(),
            stream=_EmptyAsyncResponseStream(),
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


def _policy(max_request_bytes: object = 4) -> EgressPolicy:
    """Return a policy with a deliberately small request budget."""
    return EgressPolicy.from_hosts(
        "api.openai.com",
        max_request_bytes=max_request_bytes,  # type: ignore[arg-type]
    )


def _sync_transport(*, max_request_bytes: int = 4):
    """Build an offline synchronous pinned transport and request pool."""
    pool = _SyncRequestPool()
    transport = object.__new__(_PinnedEgressTransport)
    transport._validated = _validated_result()
    transport._policy = _policy(max_request_bytes)
    transport._pool = pool
    return transport, pool


def _async_transport(*, max_request_bytes: int = 4):
    """Build an offline asynchronous pinned transport and request pool."""
    pool = _AsyncRequestPool()
    transport = object.__new__(_PinnedEgressAsyncTransport)
    transport._validated = _validated_result()
    transport._policy = _policy(max_request_bytes)
    transport._pool = pool
    return transport, pool


def _sync_request(
    stream: httpx.SyncByteStream,
    *,
    headers: tuple[tuple[bytes, bytes], ...] = (),
) -> httpx.Request:
    """Return one synchronous request matching the validated authority."""
    return httpx.Request(
        "POST",
        "https://api.openai.com/v1/uploads",
        headers=headers,
        stream=stream,
    )


def _async_request(
    stream: httpx.AsyncByteStream,
    *,
    headers: tuple[tuple[bytes, bytes], ...] = (),
) -> httpx.Request:
    """Return one asynchronous request matching the validated authority."""
    return httpx.Request(
        "POST",
        "https://api.openai.com/v1/uploads",
        headers=headers,
        stream=stream,
    )


def test_request_budget_has_a_secure_finite_default() -> None:
    """Bound upload consumption even when an operator omits configuration."""
    policy = EgressPolicy.from_hosts("api.openai.com")

    assert policy.max_request_bytes == 16 * 1024 * 1024


def test_request_budget_accepts_decimal_environment_text() -> None:
    """Normalize a positive decimal string for environment-variable use."""
    assert _policy("4096").max_request_bytes == 4096


@pytest.mark.parametrize("invalid_value", [True, 1.5, object()])
def test_request_budget_rejects_non_integer_types(invalid_value: object) -> None:
    """Reject ambiguous values that could silently disable upload bounds."""
    with pytest.raises(TypeError, match="max_request_bytes must be"):
        _policy(invalid_value)


@pytest.mark.parametrize("invalid_value", ["", "1.5", "１２", "-1", "+1"])
def test_request_budget_rejects_non_decimal_text(invalid_value: str) -> None:
    """Reject empty, signed, non-ASCII, or fractional text configuration."""
    with pytest.raises(ValueError, match="positive decimal byte count"):
        _policy(invalid_value)


@pytest.mark.parametrize("invalid_value", [0, -1])
def test_request_budget_rejects_non_positive_integers(invalid_value: int) -> None:
    """Reject zero or negative request budgets."""
    with pytest.raises(ValueError, match="greater than zero"):
        _policy(invalid_value)


def test_exact_authority_constructor_accepts_request_budget() -> None:
    """Expose the same request limit through exact authority construction."""
    policy = EgressPolicy.from_authorities(
        [("api.openai.com", 443)],
        max_request_bytes="8192",
    )

    assert policy.max_request_bytes == 8192


@pytest.mark.parametrize(
    "headers",
    [
        (),
        ((b"Content-Length", b"0"),),
        ((b"content-length", b"0004"),),
        ((b"Transfer-Encoding", b"chunked"),),
    ],
)
def test_declared_size_accepts_missing_zero_or_in_budget_lengths(
    headers: tuple[tuple[bytes, bytes], ...],
) -> None:
    """Treat declared length as an early gate, not a requirement for streaming."""
    _enforce_declared_request_size(headers, 4)


@pytest.mark.parametrize(
    "headers",
    [
        ((b"Content-Length", b"5"),),
        ((b"Content-Length", b"0000000005"),),
        ((b"Content-Length", b"999999999999999999999999999999999"),),
        ((b"Content-Length", b""),),
        ((b"Content-Length", b"4x"),),
        ((b"Content-Length", b"4"), (b"content-length", b"4")),
    ],
)
def test_declared_size_fails_closed_on_unsafe_or_oversized_metadata(
    headers: tuple[tuple[bytes, bytes], ...],
) -> None:
    """Reject malformed, duplicate, or over-budget length metadata generically."""
    with pytest.raises(EgressNotAllowedError, match="^egress URL is not allowed$"):
        _enforce_declared_request_size(headers, 4)


def test_sync_stream_forwards_exact_budget_and_delegates_close() -> None:
    """Forward every in-budget chunk and close the caller-owned source."""
    source = _ClosableSyncRequestStream((b"ab", b"cd"))
    bounded = _BoundedSyncRequestStream(source, 4)

    assert b"".join(bounded) == b"abcd"
    bounded.close()

    assert source.closed is True


def test_sync_stream_withholds_over_budget_chunk_and_preserves_generic_error() -> None:
    """Close the producer and hide its close failure when actual bytes overrun."""
    source = _ClosableSyncRequestStream(
        (b"ab", b"cde"),
        close_error=RuntimeError("attacker-controlled close failure"),
    )
    bounded = _BoundedSyncRequestStream(source, 4)
    iterator = iter(bounded)

    assert next(iterator) == b"ab"
    with pytest.raises(EgressNotAllowedError, match="^egress URL is not allowed$"):
        next(iterator)

    assert source.closed is True


async def test_async_stream_forwards_exact_budget_and_delegates_close() -> None:
    """Forward every in-budget async chunk and close the caller-owned source."""
    source = _ClosableAsyncRequestStream((b"ab", b"cd"))
    bounded = _BoundedAsyncRequestStream(source, 4)

    assert b"".join([chunk async for chunk in bounded]) == b"abcd"
    await bounded.aclose()

    assert source.closed is True


async def test_async_stream_withholds_over_budget_chunk_and_preserves_generic_error() -> None:
    """Close the async producer and hide its close failure on an actual overrun."""
    source = _ClosableAsyncRequestStream(
        (b"ab", b"cde"),
        close_error=RuntimeError("attacker-controlled close failure"),
    )
    bounded = _BoundedAsyncRequestStream(source, 4)
    iterator = aiter(bounded)

    assert await anext(iterator) == b"ab"
    with pytest.raises(EgressNotAllowedError, match="^egress URL is not allowed$"):
        await anext(iterator)

    assert source.closed is True


def test_sync_transport_rejects_oversized_declared_request_before_pool() -> None:
    """Reject a known oversized upload before connection-pool dispatch."""
    source = _ClosableSyncRequestStream((b"abcde",))
    transport, pool = _sync_transport()

    with pytest.raises(EgressNotAllowedError, match="^egress URL is not allowed$"):
        transport.handle_request(
            _sync_request(source, headers=((b"Content-Length", b"5"),))
        )

    assert pool.called is False
    assert source.closed is True


def test_sync_declared_rejection_hides_untrusted_close_failure() -> None:
    """Keep declared-size denials generic even when source cleanup raises."""
    source = _ClosableSyncRequestStream(
        (b"abcde",),
        close_error=RuntimeError("attacker-controlled close failure"),
    )
    transport, pool = _sync_transport()

    with pytest.raises(EgressNotAllowedError, match="^egress URL is not allowed$"):
        transport.handle_request(
            _sync_request(source, headers=((b"Content-Length", b"5"),))
        )

    assert pool.called is False
    assert source.closed is True


def test_sync_transport_allows_an_exact_request_budget() -> None:
    """Send and close a synchronous request whose content meets the budget."""
    source = _ClosableSyncRequestStream((b"ab", b"cd"))
    transport, pool = _sync_transport()

    response = transport.handle_request(
        _sync_request(source, headers=((b"Content-Length", b"4"),))
    )

    assert response.status_code == 204
    assert pool.body == b"abcd"
    assert source.closed is True


def test_sync_transport_stops_an_underdeclared_request_overrun() -> None:
    """Count actual streamed bytes even when Content-Length understates them."""
    source = _ClosableSyncRequestStream((b"ab", b"cde"))
    transport, pool = _sync_transport()

    with pytest.raises(EgressNotAllowedError, match="^egress URL is not allowed$"):
        transport.handle_request(
            _sync_request(source, headers=((b"Content-Length", b"2"),))
        )

    assert pool.called is True
    assert pool.body is None
    assert source.closed is True


def test_sync_transport_bounds_chunked_request_content() -> None:
    """Count unknown-length request content independently of framing metadata."""
    source = _ClosableSyncRequestStream((b"ab", b"cde"))
    transport, pool = _sync_transport()

    with pytest.raises(EgressNotAllowedError, match="^egress URL is not allowed$"):
        transport.handle_request(
            _sync_request(source, headers=((b"Transfer-Encoding", b"chunked"),))
        )

    assert pool.called is True
    assert pool.body is None
    assert source.closed is True


async def test_async_transport_rejects_oversized_declared_request_before_pool() -> None:
    """Reject a known oversized async upload before pool dispatch."""
    source = _ClosableAsyncRequestStream((b"abcde",))
    transport, pool = _async_transport()

    with pytest.raises(EgressNotAllowedError, match="^egress URL is not allowed$"):
        await transport.handle_async_request(
            _async_request(source, headers=((b"Content-Length", b"5"),))
        )

    assert pool.called is False
    assert source.closed is True


async def test_async_declared_rejection_hides_untrusted_close_failure() -> None:
    """Keep async declared-size denials generic when source cleanup raises."""
    source = _ClosableAsyncRequestStream(
        (b"abcde",),
        close_error=RuntimeError("attacker-controlled close failure"),
    )
    transport, pool = _async_transport()

    with pytest.raises(EgressNotAllowedError, match="^egress URL is not allowed$"):
        await transport.handle_async_request(
            _async_request(source, headers=((b"Content-Length", b"5"),))
        )

    assert pool.called is False
    assert source.closed is True


async def test_async_transport_allows_an_exact_request_budget() -> None:
    """Send and close an asynchronous request that meets the byte budget."""
    source = _ClosableAsyncRequestStream((b"ab", b"cd"))
    transport, pool = _async_transport()

    response = await transport.handle_async_request(
        _async_request(source, headers=((b"Content-Length", b"4"),))
    )

    assert response.status_code == 204
    assert pool.body == b"abcd"
    assert source.closed is True


async def test_async_transport_stops_an_underdeclared_request_overrun() -> None:
    """Count actual async stream bytes even when length metadata understates them."""
    source = _ClosableAsyncRequestStream((b"ab", b"cde"))
    transport, pool = _async_transport()

    with pytest.raises(EgressNotAllowedError, match="^egress URL is not allowed$"):
        await transport.handle_async_request(
            _async_request(source, headers=((b"Content-Length", b"2"),))
        )

    assert pool.called is True
    assert pool.body is None
    assert source.closed is True


async def test_async_transport_bounds_chunked_request_content() -> None:
    """Count unknown-length async request content independently of framing."""
    source = _ClosableAsyncRequestStream((b"ab", b"cde"))
    transport, pool = _async_transport()

    with pytest.raises(EgressNotAllowedError, match="^egress URL is not allowed$"):
        await transport.handle_async_request(
            _async_request(source, headers=((b"Transfer-Encoding", b"chunked"),))
        )

    assert pool.called is True
    assert pool.body is None
    assert source.closed is True
