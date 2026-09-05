"""Regressions for bounded zero-progress outbound request streams."""

from __future__ import annotations

from collections.abc import AsyncIterator, Iterator
from pathlib import Path

import httpx
import pytest

from egressweave import EgressNotAllowedError
from egressweave.request_body_safety import (
    _BoundedAsyncRequestStream,
    _BoundedSyncRequestStream,
)


class _RepeatedEmptySyncChunkStream(httpx.SyncByteStream):
    """Yield repeated empty chunks and record fail-closed cleanup."""

    def __init__(self) -> None:
        """Initialize the source closure marker."""
        self.closed = False

    def __iter__(self) -> Iterator[bytes]:
        """Model an unbounded no-write source with two observable iterations."""
        yield b""
        yield b""

    def close(self) -> None:
        """Record source closure after policy denial."""
        self.closed = True


class _RepeatedEmptyAsyncChunkStream(httpx.AsyncByteStream):
    """Yield repeated empty async chunks and record cleanup."""

    def __init__(self) -> None:
        """Initialize the asynchronous source closure marker."""
        self.closed = False

    async def __aiter__(self) -> AsyncIterator[bytes]:
        """Model an async no-write source with two observable iterations."""
        yield b""
        yield b""

    async def aclose(self) -> None:
        """Record source closure after policy denial."""
        self.closed = True


def _assert_clean_denial(error: EgressNotAllowedError) -> None:
    """Require the stable non-leaking outbound policy denial."""
    assert str(error) == "egress URL is not allowed"
    assert error.__cause__ is None
    assert error.__context__ is None


def test_sync_request_rejects_repeated_empty_chunks_before_unbounded_spin() -> None:
    """Stop a synchronous source after its second zero-progress chunk."""
    source = _RepeatedEmptySyncChunkStream()
    stream = _BoundedSyncRequestStream(source, max_request_bytes=1)

    with pytest.raises(EgressNotAllowedError) as caught:
        list(stream)

    _assert_clean_denial(caught.value)
    assert source.closed is True


async def test_async_request_rejects_repeated_empty_chunks_before_unbounded_spin() -> None:
    """Stop an asynchronous source after its second zero-progress chunk."""
    source = _RepeatedEmptyAsyncChunkStream()
    stream = _BoundedAsyncRequestStream(source, max_request_bytes=1)

    with pytest.raises(EgressNotAllowedError) as caught:
        _ = [chunk async for chunk in stream]

    _assert_clean_denial(caught.value)
    assert source.closed is True


def test_sync_request_preserves_httpx_empty_body_encoding() -> None:
    """Consume HTTPX's one canonical empty chunk without dispatching it."""
    source = httpx.ByteStream(b"")
    stream = _BoundedSyncRequestStream(
        source,
        max_request_bytes=1,
        declared_request_bytes=0,
    )

    assert list(stream) == []


async def test_async_request_preserves_httpx_empty_body_encoding() -> None:
    """Consume HTTPX's async canonical empty chunk without dispatching it."""
    source = httpx.ByteStream(b"")
    stream = _BoundedAsyncRequestStream(
        source,
        max_request_bytes=1,
        declared_request_bytes=0,
    )

    assert [chunk async for chunk in stream] == []


def test_changelog_describes_repeated_zero_progress_boundary() -> None:
    """Keep release history aligned with the one-empty-chunk compatibility rule."""
    changelog = Path("CHANGELOG.md").read_text(encoding="utf-8")

    assert "Reject repeated exact empty `bytes` chunks" in changelog
    assert "Reject exact empty `bytes` chunks" not in changelog
