"""Regression tests binding request streams to declared Content-Length values."""

from __future__ import annotations

from collections.abc import AsyncIterator, Iterator
from types import SimpleNamespace

import httpx
import pytest

from egressweave import EgressNotAllowedError, EgressPolicy
from egressweave.sync_transport import _PinnedEgressTransport
from egressweave.transport import _PinnedEgressAsyncTransport
from egressweave.validation import _make_validated_egress_url


class _SyncSource(httpx.SyncByteStream):
    """Yield deterministic request chunks and record source closure."""

    def __init__(self, chunks: tuple[bytes, ...]) -> None:
        """Store chunks and initialize the closure marker."""
        self._chunks = chunks
        self.closed = False

    def __iter__(self) -> Iterator[bytes]:
        """Yield the configured request chunks."""
        yield from self._chunks

    def close(self) -> None:
        """Record source closure."""
        self.closed = True


class _AsyncSource(httpx.AsyncByteStream):
    """Yield deterministic asynchronous chunks and record source closure."""

    def __init__(self, chunks: tuple[bytes, ...]) -> None:
        """Store chunks and initialize the closure marker."""
        self._chunks = chunks
        self.closed = False

    async def __aiter__(self) -> AsyncIterator[bytes]:
        """Yield the configured asynchronous request chunks."""
        for chunk in self._chunks:
            yield chunk

    async def aclose(self) -> None:
        """Record source closure."""
        self.closed = True


class _EmptySyncResponseStream(httpx.SyncByteStream):
    """Provide a bodyless synchronous response stream."""

    def __iter__(self) -> Iterator[bytes]:
        """Yield no response chunks."""
        return iter(())

    def close(self) -> None:
        """Close the stateless response stream."""


class _EmptyAsyncResponseStream(httpx.AsyncByteStream):
    """Provide a bodyless asynchronous response stream."""

    async def __aiter__(self) -> AsyncIterator[bytes]:
        """Yield no response chunks."""
        if False:
            yield b""

    async def aclose(self) -> None:
        """Close the stateless response stream."""


class _SyncPool:
    """Consume one synchronous request without network I/O."""

    def __init__(self) -> None:
        """Initialize observed request state."""
        self.body: bytes | None = None

    def handle_request(self, request):
        """Consume the request stream and return an HTTP 204 response."""
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


class _AsyncPool:
    """Consume one asynchronous request without network I/O."""

    def __init__(self) -> None:
        """Initialize observed asynchronous request state."""
        self.body: bytes | None = None

    async def handle_async_request(self, request):
        """Consume the request stream and return an HTTP 204 response."""
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
    """Return factory-issued validation state without DNS I/O."""
    return _make_validated_egress_url(
        "https://api.openai.com",
        "api.openai.com",
        443,
        ("93.184.216.34",),
    )


def _policy() -> EgressPolicy:
    """Return an exact authority with an eight-byte policy budget."""
    return EgressPolicy.from_hosts("api.openai.com", max_request_bytes=8)


def _sync_transport() -> tuple[_PinnedEgressTransport, _SyncPool]:
    """Build an offline synchronous transport and observing pool."""
    pool = _SyncPool()
    transport = object.__new__(_PinnedEgressTransport)
    transport._validated = _validated_result()
    transport._policy = _policy()
    transport._pool = pool
    return transport, pool


def _async_transport() -> tuple[_PinnedEgressAsyncTransport, _AsyncPool]:
    """Build an offline asynchronous transport and observing pool."""
    pool = _AsyncPool()
    transport = object.__new__(_PinnedEgressAsyncTransport)
    transport._validated = _validated_result()
    transport._policy = _policy()
    transport._pool = pool
    return transport, pool


def _sync_request(source: httpx.SyncByteStream, declared_bytes: int) -> httpx.Request:
    """Return a synchronous request with one declared content length."""
    return httpx.Request(
        "POST",
        "https://api.openai.com/v1/uploads",
        headers=((b"Content-Length", str(declared_bytes).encode("ascii")),),
        stream=source,
    )


def _async_request(source: httpx.AsyncByteStream, declared_bytes: int) -> httpx.Request:
    """Return an asynchronous request with one declared content length."""
    return httpx.Request(
        "POST",
        "https://api.openai.com/v1/uploads",
        headers=((b"Content-Length", str(declared_bytes).encode("ascii")),),
        stream=source,
    )


def test_sync_transport_rejects_actual_bytes_above_declared_length() -> None:
    """Never forward a complete sync body larger than its HTTP framing metadata."""
    source = _SyncSource((b"ab", b"cd"))
    transport, pool = _sync_transport()

    with pytest.raises(EgressNotAllowedError, match="^egress URL is not allowed$"):
        transport.handle_request(_sync_request(source, 3))

    assert pool.body is None
    assert source.closed is True


def test_sync_transport_rejects_actual_bytes_below_declared_length() -> None:
    """Fail a truncated sync body rather than completing mismatched framing."""
    source = _SyncSource((b"ab", b"cd"))
    transport, pool = _sync_transport()

    with pytest.raises(EgressNotAllowedError, match="^egress URL is not allowed$"):
        transport.handle_request(_sync_request(source, 5))

    assert pool.body is None
    assert source.closed is True


async def test_async_transport_rejects_actual_bytes_above_declared_length() -> None:
    """Never forward a complete async body larger than its framing metadata."""
    source = _AsyncSource((b"ab", b"cd"))
    transport, pool = _async_transport()

    with pytest.raises(EgressNotAllowedError, match="^egress URL is not allowed$"):
        await transport.handle_async_request(_async_request(source, 3))

    assert pool.body is None
    assert source.closed is True


async def test_async_transport_rejects_actual_bytes_below_declared_length() -> None:
    """Fail a truncated async body rather than completing mismatched framing."""
    source = _AsyncSource((b"ab", b"cd"))
    transport, pool = _async_transport()

    with pytest.raises(EgressNotAllowedError, match="^egress URL is not allowed$"):
        await transport.handle_async_request(_async_request(source, 5))

    assert pool.body is None
    assert source.closed is True
