"""Regression tests for request-budget enforcement across stream re-iteration."""

from __future__ import annotations

from collections.abc import AsyncIterator, Iterator

import httpx
import pytest

from egressweave import EgressNotAllowedError
from egressweave.request_body_safety import (
    _BoundedAsyncRequestStream,
    _BoundedSyncRequestStream,
)


class _ReplayableSyncStream(httpx.SyncByteStream):
    """Replay the same chunk sequence every time a consumer iterates the stream."""

    def __init__(self, chunks: tuple[bytes, ...]) -> None:
        """Store replayable chunks and initialize the closure marker."""
        self._chunks = chunks
        self.closed = False

    def __iter__(self) -> Iterator[bytes]:
        """Yield the complete chunk sequence for each independent iteration."""
        yield from self._chunks

    def close(self) -> None:
        """Record that the bounded wrapper terminated the source."""
        self.closed = True


class _ReplayableAsyncStream(httpx.AsyncByteStream):
    """Replay the same asynchronous chunks for every independent iteration."""

    def __init__(self, chunks: tuple[bytes, ...]) -> None:
        """Store replayable chunks and initialize the closure marker."""
        self._chunks = chunks
        self.closed = False

    async def __aiter__(self) -> AsyncIterator[bytes]:
        """Yield the complete chunk sequence for each asynchronous iteration."""
        for chunk in self._chunks:
            yield chunk

    async def aclose(self) -> None:
        """Record that the bounded wrapper terminated the source."""
        self.closed = True


class _OneShotSyncStream(httpx.SyncByteStream):
    """Expose one iterator that is exhausted after its first consumption."""

    def __init__(self, chunks: tuple[bytes, ...]) -> None:
        """Create the one-shot iterator and initialize the closure marker."""
        self._iterator = iter(chunks)
        self.closed = False

    def __iter__(self) -> Iterator[bytes]:
        """Return the same possibly exhausted iterator for every attempt."""
        return self._iterator

    def close(self) -> None:
        """Record that the bounded wrapper terminated the source."""
        self.closed = True


class _OneShotAsyncStream(httpx.AsyncByteStream):
    """Yield configured chunks once and remain exhausted on later attempts."""

    def __init__(self, chunks: tuple[bytes, ...]) -> None:
        """Store chunks and initialize one-shot and closure state."""
        self._chunks = chunks
        self._consumed = False
        self.closed = False

    async def __aiter__(self) -> AsyncIterator[bytes]:
        """Yield the chunks only during the first asynchronous iteration."""
        if self._consumed:
            return
        self._consumed = True
        for chunk in self._chunks:
            yield chunk

    async def aclose(self) -> None:
        """Record that the bounded wrapper terminated the source."""
        self.closed = True


def test_sync_request_budget_is_cumulative_across_reiteration() -> None:
    """Prevent a replayable sync stream from resetting its byte budget."""
    source = _ReplayableSyncStream((b"abc",))
    bounded = _BoundedSyncRequestStream(source, 4)

    assert b"".join(bounded) == b"abc"
    with pytest.raises(EgressNotAllowedError, match="^egress URL is not allowed$"):
        b"".join(bounded)

    assert source.closed is True


async def test_async_request_budget_is_cumulative_across_reiteration() -> None:
    """Prevent a replayable async stream from resetting its byte budget."""
    source = _ReplayableAsyncStream((b"abc",))
    bounded = _BoundedAsyncRequestStream(source, 4)

    assert b"".join([chunk async for chunk in bounded]) == b"abc"
    with pytest.raises(EgressNotAllowedError, match="^egress URL is not allowed$"):
        b"".join([chunk async for chunk in bounded])

    assert source.closed is True


def test_sync_retry_rejects_an_exhausted_declared_length_stream() -> None:
    """Do not accept zero retry bytes because a prior attempt met the declaration."""
    source = _OneShotSyncStream((b"abc",))
    bounded = _BoundedSyncRequestStream(source, 6, declared_request_bytes=3)

    assert b"".join(bounded) == b"abc"
    with pytest.raises(EgressNotAllowedError, match="^egress URL is not allowed$"):
        b"".join(bounded)

    assert source.closed is True


async def test_async_retry_rejects_an_exhausted_declared_length_stream() -> None:
    """Do not accept an exhausted async retry after one complete body attempt."""
    source = _OneShotAsyncStream((b"abc",))
    bounded = _BoundedAsyncRequestStream(source, 6, declared_request_bytes=3)

    assert b"".join([chunk async for chunk in bounded]) == b"abc"
    with pytest.raises(EgressNotAllowedError, match="^egress URL is not allowed$"):
        b"".join([chunk async for chunk in bounded])

    assert source.closed is True
