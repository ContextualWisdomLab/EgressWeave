"""Regression tests for exact-byte response stream accounting.

The bounded response wrappers sit at a dependency-injected backend boundary. Runtime
stream implementations are therefore treated as untrusted even though HTTPX's type
contract says they yield bytes. These tests prove malformed chunks cannot influence
resource accounting or escape the stable EgressWeave rejection boundary.
"""

from __future__ import annotations

import asyncio

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


class _SynchronousCleanupFailureAsyncStream(httpx.AsyncByteStream):
    """Raise before returning an awaitable from injected async cleanup."""

    def __init__(self, chunk: object) -> None:
        """Store one unsafe chunk and record whether cleanup was attempted."""
        self._chunk = chunk
        self.closed = False

    async def __aiter__(self):
        """Yield the configured unsafe chunk before policy cleanup runs."""
        yield self._chunk

    def aclose(self):
        """Model an injected stream that violates the static awaitable contract."""
        self.closed = True
        raise RuntimeError("private synchronous async-cleanup failure")


class _SelfCancellingCleanupAsyncStream(httpx.AsyncByteStream):
    """Raise child ``CancelledError`` from policy-denial cleanup."""

    def __init__(self, chunk: object) -> None:
        """Store one unsafe chunk and record whether cleanup was attempted."""
        self._chunk = chunk
        self.closed = False

    async def __aiter__(self):
        """Yield the configured unsafe chunk before policy cleanup runs."""
        yield self._chunk

    async def aclose(self) -> None:
        """Model an injected child stream that self-cancels during cleanup."""
        self.closed = True
        raise asyncio.CancelledError("private backend cleanup cancellation")


class _BlockingCleanupAsyncStream(httpx.AsyncByteStream):
    """Block in cleanup so cancellation directed at the caller stays visible."""

    def __init__(self, chunk: object, close_started: asyncio.Event) -> None:
        """Store one unsafe chunk and a signal for deterministic cancellation."""
        self._chunk = chunk
        self._close_started = close_started
        self.closed = False

    async def __aiter__(self):
        """Yield the configured unsafe chunk before policy cleanup runs."""
        yield self._chunk

    async def aclose(self) -> None:
        """Signal cleanup entry and wait until the caller task is cancelled."""
        self.closed = True
        self._close_started.set()
        await asyncio.Event().wait()


def _assert_clean_policy_denial(error: EgressNotAllowedError) -> None:
    """Require a generic denial with no retained backend exception provenance."""
    assert str(error) == "egress URL is not allowed"
    assert error.__context__ is None
    assert error.__cause__ is None


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


def test_sync_malformed_denial_discards_cleanup_exception_provenance() -> None:
    """Discard hostile sync cleanup provenance before creating the denial."""
    source = _MalformedSyncStream(bytearray(b"abc"), close_fails=True)
    stream = _BoundedSyncResponseStream(source, max_response_bytes=4)

    with pytest.raises(EgressNotAllowedError) as exc_info:
        next(iter(stream))

    _assert_clean_policy_denial(exc_info.value)
    assert source.closed is True


def test_sync_over_budget_denial_discards_cleanup_exception_provenance() -> None:
    """Discard hostile sync cleanup provenance on an over-budget exact chunk."""
    source = _MalformedSyncStream(b"abcde", close_fails=True)
    stream = _BoundedSyncResponseStream(source, max_response_bytes=4)

    with pytest.raises(EgressNotAllowedError) as exc_info:
        next(iter(stream))

    _assert_clean_policy_denial(exc_info.value)
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


async def test_async_malformed_denial_discards_cleanup_exception_provenance() -> None:
    """Discard hostile async cleanup provenance before creating the denial."""
    source = _MalformedAsyncStream(bytearray(b"abc"), close_fails=True)
    stream = _BoundedAsyncResponseStream(source, max_response_bytes=4)

    with pytest.raises(EgressNotAllowedError) as exc_info:
        await anext(stream.__aiter__())

    _assert_clean_policy_denial(exc_info.value)
    assert source.closed is True


async def test_async_over_budget_denial_discards_cleanup_exception_provenance() -> None:
    """Discard hostile async cleanup provenance on an over-budget exact chunk."""
    source = _MalformedAsyncStream(b"abcde", close_fails=True)
    stream = _BoundedAsyncResponseStream(source, max_response_bytes=4)

    with pytest.raises(EgressNotAllowedError) as exc_info:
        await anext(stream.__aiter__())

    _assert_clean_policy_denial(exc_info.value)
    assert source.closed is True


@pytest.mark.parametrize("chunk", [bytearray(b"abc"), b"abcde"])
async def test_async_policy_denial_masks_synchronous_cleanup_failure(
    chunk: object,
) -> None:
    """Mask a call-time cleanup error from an injected async stream."""
    source = _SynchronousCleanupFailureAsyncStream(chunk)
    stream = _BoundedAsyncResponseStream(source, max_response_bytes=4)

    with pytest.raises(EgressNotAllowedError) as exc_info:
        await anext(stream.__aiter__())

    _assert_clean_policy_denial(exc_info.value)
    assert source.closed is True


@pytest.mark.parametrize("chunk", [bytearray(b"abc"), b"abcde"])
async def test_async_policy_denial_masks_child_cleanup_cancellation(chunk: object) -> None:
    """Treat child self-cancellation as hostile cleanup, not caller cancellation."""
    source = _SelfCancellingCleanupAsyncStream(chunk)
    stream = _BoundedAsyncResponseStream(source, max_response_bytes=4)

    with pytest.raises(EgressNotAllowedError) as exc_info:
        await anext(stream.__aiter__())

    _assert_clean_policy_denial(exc_info.value)
    assert source.closed is True


async def test_async_policy_denial_preserves_caller_cancellation() -> None:
    """Propagate cancellation directed at the caller while cleanup is awaited."""
    close_started = asyncio.Event()
    source = _BlockingCleanupAsyncStream(bytearray(b"abc"), close_started)
    stream = _BoundedAsyncResponseStream(source, max_response_bytes=4)
    consume_task = asyncio.create_task(anext(stream.__aiter__()))

    await asyncio.wait_for(close_started.wait(), timeout=1.0)
    consume_task.cancel()

    with pytest.raises(asyncio.CancelledError):
        _ = await consume_task

    assert source.closed is True
