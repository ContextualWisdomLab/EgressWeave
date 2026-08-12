"""Regressions for exact response-stream chunk accounting."""

from __future__ import annotations

from collections.abc import AsyncIterator, Iterator

import httpx
import pytest

from egressweave import EgressNotAllowedError
from egressweave.response_safety import (
    _BoundedAsyncResponseStream,
    _BoundedSyncResponseStream,
)


class _LyingBytes(bytes):
    """Expose bytes while hiding their real size from polymorphic accounting."""

    def __len__(self) -> int:
        """Return a false zero length if the wrapper trusts subclass behavior."""
        return 0


class _SyncResponseSource(httpx.SyncByteStream):
    """Yield one configured response chunk and record deterministic cleanup."""

    def __init__(self, chunk: object) -> None:
        """Store the dependency-controlled response chunk."""
        self.chunk = chunk
        self.closed = False

    def __iter__(self) -> Iterator[bytes]:
        """Yield the configured object despite the static bytes contract."""
        yield self.chunk  # type: ignore[misc]

    def close(self) -> None:
        """Record that the rejected dependency stream was released."""
        self.closed = True


class _AsyncResponseSource(httpx.AsyncByteStream):
    """Yield one configured async response chunk and record cleanup."""

    def __init__(self, chunk: object) -> None:
        """Store the dependency-controlled response chunk."""
        self.chunk = chunk
        self.closed = False

    async def __aiter__(self) -> AsyncIterator[bytes]:
        """Yield the configured object despite the static bytes contract."""
        yield self.chunk  # type: ignore[misc]

    async def aclose(self) -> None:
        """Record that the rejected dependency stream was released."""
        self.closed = True


def _assert_clean_denial(error: EgressNotAllowedError) -> None:
    """Require the stable non-leaking response policy denial."""
    assert str(error) == "egress URL is not allowed"
    assert error.__cause__ is None
    assert error.__context__ is None


def test_sync_response_rejects_bytes_subclass_before_length_accounting() -> None:
    """Prevent a response bytes subclass from under-reporting its body size."""
    source = _SyncResponseSource(_LyingBytes(b"0123456789"))
    stream = _BoundedSyncResponseStream(source, max_response_bytes=4)

    with pytest.raises(EgressNotAllowedError) as caught:
        next(iter(stream))

    _assert_clean_denial(caught.value)
    assert source.closed is True


async def test_async_response_rejects_bytes_subclass_before_length_accounting() -> None:
    """Apply exact response-chunk accounting to the asynchronous boundary."""
    source = _AsyncResponseSource(_LyingBytes(b"0123456789"))
    stream = _BoundedAsyncResponseStream(source, max_response_bytes=4)

    with pytest.raises(EgressNotAllowedError) as caught:
        await anext(stream.__aiter__())

    _assert_clean_denial(caught.value)
    assert source.closed is True
