"""Regression tests for fail-closed request-stream chunk typing."""

from __future__ import annotations

from collections.abc import AsyncIterator, Iterator

import httpx
import pytest

from egressweave import EgressNotAllowedError
from egressweave.request_body_safety import (
    _BoundedAsyncRequestStream,
    _BoundedSyncRequestStream,
)


class _InvalidSyncChunkStream(httpx.SyncByteStream):
    """Yield a text chunk that violates the HTTPX byte-stream contract."""

    def __init__(self) -> None:
        """Initialize the source closure marker."""
        self.closed = False

    def __iter__(self) -> Iterator[bytes]:
        """Yield one intentionally invalid non-byte chunk."""
        yield "secret-text"  # type: ignore[misc]

    def close(self) -> None:
        """Record source closure after fail-closed validation."""
        self.closed = True


class _InvalidAsyncChunkStream(httpx.AsyncByteStream):
    """Yield a text chunk that violates the async byte-stream contract."""

    def __init__(self) -> None:
        """Initialize the asynchronous source closure marker."""
        self.closed = False

    async def __aiter__(self) -> AsyncIterator[bytes]:
        """Yield one intentionally invalid non-byte chunk."""
        yield "secret-text"  # type: ignore[misc]

    async def aclose(self) -> None:
        """Record source closure after fail-closed validation."""
        self.closed = True


def test_sync_non_byte_chunk_fails_with_generic_denial() -> None:
    """Reject invalid sync chunks before they reach HTTPCore or reveal values."""
    source = _InvalidSyncChunkStream()
    bounded = _BoundedSyncRequestStream(source, 1024)

    with pytest.raises(EgressNotAllowedError, match="^egress URL is not allowed$"):
        next(iter(bounded))

    assert source.closed is True


async def test_async_non_byte_chunk_fails_with_generic_denial() -> None:
    """Reject invalid async chunks before HTTPCore receives or reports them."""
    source = _InvalidAsyncChunkStream()
    bounded = _BoundedAsyncRequestStream(source, 1024)

    with pytest.raises(EgressNotAllowedError, match="^egress URL is not allowed$"):
        await anext(bounded.__aiter__())

    assert source.closed is True
