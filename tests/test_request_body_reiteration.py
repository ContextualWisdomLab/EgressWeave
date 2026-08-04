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
