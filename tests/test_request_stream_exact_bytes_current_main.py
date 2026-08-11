"""Current-main regressions for exact-byte request stream accounting."""

from __future__ import annotations

import httpx
import pytest

from egressweave import EgressNotAllowedError
from egressweave.request_body_safety import (
    _BoundedAsyncRequestStream,
    _BoundedSyncRequestStream,
)


class _ExplodingBytes(bytes):
    """Raise if request accounting trusts a bytes-subclass length method."""

    def __len__(self) -> int:
        """Expose the polymorphic behavior that must not cross the boundary."""
        raise RuntimeError("private request stream length failure")


class _SyncSource(httpx.SyncByteStream):
    """Yield one dependency-controlled chunk and record cleanup."""

    def __init__(self, chunk: bytes) -> None:
        self._chunk = chunk
        self.closed = False

    def __iter__(self):
        yield self._chunk

    def close(self) -> None:
        self.closed = True


class _AsyncSource(httpx.AsyncByteStream):
    """Yield one dependency-controlled async chunk and record cleanup."""

    def __init__(self, chunk: bytes) -> None:
        self._chunk = chunk
        self.closed = False

    async def __aiter__(self):
        yield self._chunk

    async def aclose(self) -> None:
        self.closed = True


def test_sync_request_stream_rejects_bytes_subclass_before_length_dispatch() -> None:
    """Reject polymorphic bytes before subclass-controlled accounting executes."""
    source = _SyncSource(_ExplodingBytes(b"abc"))
    stream = _BoundedSyncRequestStream(source, max_request_bytes=4)

    with pytest.raises(EgressNotAllowedError, match="^egress URL is not allowed$"):
        next(iter(stream))

    assert source.closed is True


async def test_async_request_stream_rejects_bytes_subclass_before_length_dispatch() -> None:
    """Apply the same exact-byte boundary to asynchronous request streams."""
    source = _AsyncSource(_ExplodingBytes(b"abc"))
    stream = _BoundedAsyncRequestStream(source, max_request_bytes=4)

    with pytest.raises(EgressNotAllowedError, match="^egress URL is not allowed$"):
        await anext(stream.__aiter__())

    assert source.closed is True
