"""Regression tests for exact-byte request stream accounting.

The bounded request wrappers sit between application-provided HTTPX streams and
HTTPCore. Runtime stream implementations are therefore treated as untrusted even
though the static HTTPX contract says they yield bytes. These tests prove that a
malformed chunk cannot influence resource accounting or escape the stable
EgressWeave rejection boundary.
"""

from __future__ import annotations

import httpx
import pytest

from egressweave import EgressNotAllowedError
from egressweave.request_body_safety import (
    _BoundedAsyncRequestStream,
    _BoundedSyncRequestStream,
)


class _LyingBytes(bytes):
    """Expose real bytes while deliberately under-reporting their length."""

    def __len__(self) -> int:
        """Return a false zero length to model a hostile bytes subclass."""
        return 0


class _ExplodingBytes(bytes):
    """Raise if request accounting trusts an overridable bytes-subclass length."""

    def __len__(self) -> int:
        """Raise a private source error that must never cross the boundary."""
        raise RuntimeError("private request stream length failure")


class _MalformedSyncRequestStream(httpx.SyncByteStream):
    """Yield one deliberately malformed synchronous chunk and record closure."""

    def __init__(self, chunk: object, *, close_fails: bool = False) -> None:
        """Store the malformed chunk and optional hostile cleanup behavior."""
        self._chunk = chunk
        self._close_fails = close_fails
        self.closed = False

    def __iter__(self):
        """Yield the configured object despite the static byte-stream contract."""
        yield self._chunk

    def close(self) -> None:
        """Record cleanup and optionally model a hostile source close failure."""
        self.closed = True
        if self._close_fails:
            raise RuntimeError("private request stream close failure")


class _MalformedAsyncRequestStream(httpx.AsyncByteStream):
    """Yield one deliberately malformed asynchronous chunk and record closure."""

    def __init__(self, chunk: object, *, close_fails: bool = False) -> None:
        """Store the malformed chunk and optional hostile cleanup behavior."""
        self._chunk = chunk
        self._close_fails = close_fails
        self.closed = False

    async def __aiter__(self):
        """Yield the configured object despite the static byte-stream contract."""
        yield self._chunk

    async def aclose(self) -> None:
        """Record cleanup and optionally model a hostile source close failure."""
        self.closed = True
        if self._close_fails:
            raise RuntimeError("private request stream close failure")


@pytest.mark.parametrize(
    "chunk",
    [
        _LyingBytes(b"0123456789"),
        _ExplodingBytes(b"abc"),
        bytearray(b"abc"),
    ],
)
def test_sync_request_stream_rejects_non_exact_bytes_and_closes(chunk: object) -> None:
    """Reject malformed sync chunks before length accounting or downstream yield."""
    source = _MalformedSyncRequestStream(chunk)
    stream = _BoundedSyncRequestStream(source, max_request_bytes=4)

    with pytest.raises(EgressNotAllowedError, match="^egress URL is not allowed$"):
        next(iter(stream))

    assert source.closed is True


def test_sync_malformed_request_chunk_masks_cleanup_failure() -> None:
    """Keep hostile synchronous cleanup details behind the stable policy error."""
    source = _MalformedSyncRequestStream(bytearray(b"abc"), close_fails=True)
    stream = _BoundedSyncRequestStream(source, max_request_bytes=4)

    with pytest.raises(EgressNotAllowedError, match="^egress URL is not allowed$"):
        next(iter(stream))

    assert source.closed is True


def test_sync_request_stream_preserves_exact_bytes_accounting() -> None:
    """Keep exact built-in bytes valid at the configured request-byte ceiling."""
    source = _MalformedSyncRequestStream(b"abcd")
    stream = _BoundedSyncRequestStream(source, max_request_bytes=4)

    assert list(stream) == [b"abcd"]
    stream.close()
    assert source.closed is True


@pytest.mark.parametrize(
    "chunk",
    [
        _LyingBytes(b"0123456789"),
        _ExplodingBytes(b"abc"),
        bytearray(b"abc"),
    ],
)
async def test_async_request_stream_rejects_non_exact_bytes_and_closes(
    chunk: object,
) -> None:
    """Reject malformed async chunks before length accounting or downstream yield."""
    source = _MalformedAsyncRequestStream(chunk)
    stream = _BoundedAsyncRequestStream(source, max_request_bytes=4)

    with pytest.raises(EgressNotAllowedError, match="^egress URL is not allowed$"):
        await anext(stream.__aiter__())

    assert source.closed is True


async def test_async_malformed_request_chunk_masks_cleanup_failure() -> None:
    """Keep hostile asynchronous cleanup details behind the stable policy error."""
    source = _MalformedAsyncRequestStream(bytearray(b"abc"), close_fails=True)
    stream = _BoundedAsyncRequestStream(source, max_request_bytes=4)

    with pytest.raises(EgressNotAllowedError, match="^egress URL is not allowed$"):
        await anext(stream.__aiter__())

    assert source.closed is True


async def test_async_request_stream_preserves_exact_bytes_accounting() -> None:
    """Keep exact built-in bytes valid at the configured async request ceiling."""
    source = _MalformedAsyncRequestStream(b"abcd")
    stream = _BoundedAsyncRequestStream(source, max_request_bytes=4)

    assert [chunk async for chunk in stream] == [b"abcd"]
    await stream.aclose()
    assert source.closed is True
