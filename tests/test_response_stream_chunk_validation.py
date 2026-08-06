"""Regression tests for exact-byte response stream accounting.

The bounded response wrappers sit at a dependency-injected backend boundary. Runtime
stream implementations are therefore treated as untrusted even though HTTPX's type
contract says they yield bytes. These tests prove malformed chunks cannot influence
resource accounting or escape the stable EgressWeave rejection boundary.
"""

from __future__ import annotations

import httpx
import pytest

from egressweave import EgressNotAllowedError
from egressweave.response_safety import (
    _BoundedAsyncResponseStream,
    _BoundedSyncResponseStream,
)


class _LyingBytes(bytes):
    """Expose real bytes while deliberately under-reporting their length."""

    def __len__(self) -> int:
        """Return a false zero length to model a hostile bytes subclass."""
        return 0


class _ExplodingLength:
    """Raise if resource accounting trusts an arbitrary length protocol."""

    def __len__(self) -> int:
        """Raise a private backend error that must never cross the boundary."""
        raise RuntimeError("private backend length failure")


class _MalformedSyncStream(httpx.SyncByteStream):
    """Yield one deliberately malformed sync chunk and record closure."""

    def __init__(self, chunk: object, *, close_fails: bool = False) -> None:
        """Store the malformed chunk and optional hostile cleanup behavior."""
        self._chunk = chunk
        self._close_fails = close_fails
        self.closed = False

    def __iter__(self):
        """Yield the configured object despite the static byte-stream contract."""
        yield self._chunk

    def close(self) -> None:
        """Record cleanup and optionally model a hostile backend close failure."""
        self.closed = True
        if self._close_fails:
            raise RuntimeError("private backend close failure")


class _MalformedAsyncStream(httpx.AsyncByteStream):
    """Yield one deliberately malformed async chunk and record closure."""

    def __init__(self, chunk: object, *, close_fails: bool = False) -> None:
        """Store the malformed chunk and optional hostile cleanup behavior."""
        self._chunk = chunk
        self._close_fails = close_fails
        self.closed = False

    async def __aiter__(self):
        """Yield the configured object despite the static byte-stream contract."""
        yield self._chunk

    async def aclose(self) -> None:
        """Record cleanup and optionally model a hostile backend close failure."""
        self.closed = True
        if self._close_fails:
            raise RuntimeError("private backend close failure")


@pytest.mark.parametrize(
    "chunk",
    [
        _LyingBytes(b"0123456789"),
        bytearray(b"abc"),
        _ExplodingLength(),
    ],
)
def test_sync_response_stream_rejects_non_exact_bytes_and_closes(chunk: object) -> None:
    """Reject malformed sync chunks before length accounting or caller delivery."""
    source = _MalformedSyncStream(chunk)
    stream = _BoundedSyncResponseStream(source, max_response_bytes=4)

    with pytest.raises(EgressNotAllowedError, match="^egress URL is not allowed$"):
        next(iter(stream))

    assert source.closed is True


def test_sync_malformed_chunk_masks_cleanup_failure() -> None:
    """Keep hostile sync cleanup details behind the stable policy boundary."""
    source = _MalformedSyncStream(bytearray(b"abc"), close_fails=True)
    stream = _BoundedSyncResponseStream(source, max_response_bytes=4)

    with pytest.raises(EgressNotAllowedError, match="^egress URL is not allowed$"):
        next(iter(stream))

    assert source.closed is True


@pytest.mark.parametrize(
    "chunk",
    [
        _LyingBytes(b"0123456789"),
        bytearray(b"abc"),
        _ExplodingLength(),
    ],
)
async def test_async_response_stream_rejects_non_exact_bytes_and_closes(
    chunk: object,
) -> None:
    """Reject malformed async chunks before length accounting or caller delivery."""
    source = _MalformedAsyncStream(chunk)
    stream = _BoundedAsyncResponseStream(source, max_response_bytes=4)

    with pytest.raises(EgressNotAllowedError, match="^egress URL is not allowed$"):
        await anext(stream.__aiter__())

    assert source.closed is True


async def test_async_malformed_chunk_masks_cleanup_failure() -> None:
    """Keep hostile async cleanup details behind the stable policy boundary."""
    source = _MalformedAsyncStream(bytearray(b"abc"), close_fails=True)
    stream = _BoundedAsyncResponseStream(source, max_response_bytes=4)

    with pytest.raises(EgressNotAllowedError, match="^egress URL is not allowed$"):
        await anext(stream.__aiter__())

    assert source.closed is True
