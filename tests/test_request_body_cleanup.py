"""Cleanup and metadata edge cases for outbound request-body budgets."""

from __future__ import annotations

from collections.abc import AsyncIterator, Iterator

import httpx
import pytest

from egressweave import EgressNotAllowedError, EgressPolicy
from egressweave.request_body_safety import (
    _BoundedAsyncRequestStream,
    _BoundedSyncRequestStream,
    _enforce_declared_request_size,
)
from egressweave.sync_transport import _PinnedEgressTransport
from egressweave.transport import _PinnedEgressAsyncTransport
from egressweave.validation import _make_validated_egress_url


class _FailingCloseSyncStream(httpx.SyncByteStream):
    """Yield request chunks and raise an untrusted error during cleanup."""

    def __init__(self, chunks: tuple[bytes, ...]) -> None:
        """Store chunks and initialize the closure marker."""
        self._chunks = chunks
        self.closed = False

    def __iter__(self) -> Iterator[bytes]:
        """Yield the configured chunks."""
        yield from self._chunks

    def close(self) -> None:
        """Record closure and simulate an attacker-controlled cleanup failure."""
        self.closed = True
        raise RuntimeError("attacker-controlled close failure")


class _FailingCloseAsyncStream(httpx.AsyncByteStream):
    """Yield async request chunks and raise an untrusted cleanup error."""

    def __init__(self, chunks: tuple[bytes, ...]) -> None:
        """Store chunks and initialize the closure marker."""
        self._chunks = chunks
        self.closed = False

    async def __aiter__(self) -> AsyncIterator[bytes]:
        """Yield the configured chunks asynchronously."""
        for chunk in self._chunks:
            yield chunk

    async def aclose(self) -> None:
        """Record closure and simulate an attacker-controlled cleanup failure."""
        self.closed = True
        raise RuntimeError("attacker-controlled close failure")


class _UnexpectedSyncPool:
    """Fail if a rejected synchronous request reaches pool dispatch."""

    def handle_request(self, request) -> None:
        """Reject unexpected pool dispatch."""
        raise AssertionError("request reached the synchronous pool")


class _UnexpectedAsyncPool:
    """Fail if a rejected asynchronous request reaches pool dispatch."""

    async def handle_async_request(self, request) -> None:
        """Reject unexpected asynchronous pool dispatch."""
        raise AssertionError("request reached the asynchronous pool")


def _validated_result():
    """Return factory-issued state without DNS or network I/O."""
    return _make_validated_egress_url(
        "https://api.openai.com",
        "api.openai.com",
        443,
        ("93.184.216.34",),
    )


def _policy() -> EgressPolicy:
    """Return one exact authority with a four-byte request budget."""
    return EgressPolicy.from_hosts("api.openai.com", max_request_bytes=4)


def _sync_transport() -> _PinnedEgressTransport:
    """Build an offline synchronous transport for preflight testing."""
    transport = object.__new__(_PinnedEgressTransport)
    transport._validated = _validated_result()
    transport._policy = _policy()
    transport._pool = _UnexpectedSyncPool()
    return transport


def _async_transport() -> _PinnedEgressAsyncTransport:
    """Build an offline asynchronous transport for preflight testing."""
    transport = object.__new__(_PinnedEgressAsyncTransport)
    transport._validated = _validated_result()
    transport._policy = _policy()
    transport._pool = _UnexpectedAsyncPool()
    return transport


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
    """Treat declared length as an early gate rather than a stream requirement."""
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
def test_declared_size_rejects_unsafe_or_oversized_metadata(
    headers: tuple[tuple[bytes, bytes], ...],
) -> None:
    """Reject malformed, duplicate, or over-budget length metadata generically."""
    with pytest.raises(EgressNotAllowedError, match="^egress URL is not allowed$"):
        _enforce_declared_request_size(headers, 4)


def test_sync_stream_overrun_masks_untrusted_close_failure() -> None:
    """Preserve the generic denial if synchronous source cleanup raises."""
    source = _FailingCloseSyncStream((b"ab", b"cde"))
    iterator = iter(_BoundedSyncRequestStream(source, 4))

    assert next(iterator) == b"ab"
    with pytest.raises(EgressNotAllowedError, match="^egress URL is not allowed$"):
        next(iterator)

    assert source.closed is True


async def test_async_stream_overrun_masks_untrusted_close_failure() -> None:
    """Preserve the generic denial if asynchronous source cleanup raises."""
    source = _FailingCloseAsyncStream((b"ab", b"cde"))
    iterator = aiter(_BoundedAsyncRequestStream(source, 4))

    assert await anext(iterator) == b"ab"
    with pytest.raises(EgressNotAllowedError, match="^egress URL is not allowed$"):
        await anext(iterator)

    assert source.closed is True


def test_sync_declared_rejection_masks_untrusted_close_failure() -> None:
    """Keep synchronous preflight denial generic when source cleanup raises."""
    source = _FailingCloseSyncStream((b"abcde",))
    request = httpx.Request(
        "POST",
        "https://api.openai.com/v1/uploads",
        headers=((b"Content-Length", b"5"),),
        stream=source,
    )

    with pytest.raises(EgressNotAllowedError, match="^egress URL is not allowed$"):
        _sync_transport().handle_request(request)

    assert source.closed is True


async def test_async_declared_rejection_masks_untrusted_close_failure() -> None:
    """Keep asynchronous preflight denial generic when source cleanup raises."""
    source = _FailingCloseAsyncStream((b"abcde",))
    request = httpx.Request(
        "POST",
        "https://api.openai.com/v1/uploads",
        headers=((b"Content-Length", b"5"),),
        stream=source,
    )

    with pytest.raises(EgressNotAllowedError, match="^egress URL is not allowed$"):
        await _async_transport().handle_async_request(request)

    assert source.closed is True
