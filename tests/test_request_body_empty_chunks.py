"""Regressions for zero-progress outbound request streams."""

from __future__ import annotations

from collections.abc import AsyncIterator, Iterator

import httpx
import pytest

from egressweave import EgressNotAllowedError
from egressweave.request_body_safety import (
    _BoundedAsyncRequestStream,
    _BoundedSyncRequestStream,
)


class _EmptySyncChunkStream(httpx.SyncByteStream):
    """Yield one empty byte chunk and record fail-closed cleanup."""

    def __init__(self) -> None:
        """Initialize the source closure marker."""
        self.closed = False

    def __iter__(self) -> Iterator[bytes]:
        """Yield a chunk that consumes no byte budget and makes no progress."""
        yield b""

    def close(self) -> None:
        """Record source closure after policy denial."""
        self.closed = True


class _EmptyAsyncChunkStream(httpx.AsyncByteStream):
    """Yield one empty async byte chunk and record cleanup."""

    def __init__(self) -> None:
        """Initialize the asynchronous source closure marker."""
        self.closed = False

    async def __aiter__(self) -> AsyncIterator[bytes]:
        """Yield a chunk that consumes no byte budget and makes no progress."""
        yield b""

    async def aclose(self) -> None:
        """Record source closure after policy denial."""
        self.closed = True


def _assert_clean_denial(error: EgressNotAllowedError) -> None:
    """Require the stable non-leaking outbound policy denial."""
    assert str(error) == "egress URL is not allowed"
    assert error.__cause__ is None
    assert error.__context__ is None


def test_sync_request_rejects_empty_chunk_before_dispatch_progress() -> None:
    """Prevent a synchronous body from spinning on zero-progress chunks."""
    source = _EmptySyncChunkStream()
    stream = _BoundedSyncRequestStream(source, max_request_bytes=1)

    with pytest.raises(EgressNotAllowedError) as caught:
        next(iter(stream))

    _assert_clean_denial(caught.value)
    assert source.closed is True


async def test_async_request_rejects_empty_chunk_before_dispatch_progress() -> None:
    """Prevent an asynchronous body from spinning on zero-progress chunks."""
    source = _EmptyAsyncChunkStream()
    stream = _BoundedAsyncRequestStream(source, max_request_bytes=1)

    with pytest.raises(EgressNotAllowedError) as caught:
        await anext(stream.__aiter__())

    _assert_clean_denial(caught.value)
    assert source.closed is True
