"""Current-main regressions for exact request bytes and denial cleanup."""

from __future__ import annotations

import httpx
import pytest

from egressweave import EgressNotAllowedError
from egressweave.request_body_safety import (
    _BoundedAsyncRequestStream,
    _BoundedSyncRequestStream,
)


class _LyingBytes(bytes):
    """Expose bytes while under-reporting their length."""

    def __len__(self) -> int:
        """Return a false zero length if accounting trusts subclass behavior."""
        return 0


class _DirectCleanupBaseError(BaseException):
    """Model a dependency-controlled cleanup failure outside Exception."""


class _SyncSource(httpx.SyncByteStream):
    """Yield one configured object and optionally fail during cleanup."""

    def __init__(self, chunk: object, failure: BaseException | None = None) -> None:
        """Store the untrusted chunk and optional cleanup failure."""
        self.chunk = chunk
        self.failure = failure
        self.closed = False

    def __iter__(self):
        """Yield the configured object despite the static bytes contract."""
        yield self.chunk

    def close(self) -> None:
        """Record cleanup and raise the configured dependency failure."""
        self.closed = True
        if self.failure is not None:
            raise self.failure


class _AsyncSource(httpx.AsyncByteStream):
    """Yield one configured object and optionally fail before cleanup awaits."""

    def __init__(self, chunk: object, failure: BaseException | None = None) -> None:
        """Store the untrusted chunk and optional cleanup failure."""
        self.chunk = chunk
        self.failure = failure
        self.closed = False

    async def __aiter__(self):
        """Yield the configured object despite the static bytes contract."""
        yield self.chunk

    def aclose(self):
        """Record cleanup and fail before returning an awaitable when configured."""
        self.closed = True
        if self.failure is not None:
            raise self.failure

        async def _done() -> None:
            return None

        return _done()


def _assert_clean_denial(error: EgressNotAllowedError) -> None:
    """Require the stable non-leaking policy denial."""
    assert str(error) == "egress URL is not allowed"
    assert error.__cause__ is None
    assert error.__context__ is None


def test_sync_rejects_bytes_subclass_before_length_behavior() -> None:
    """Do not allow a bytes subclass to falsify cumulative accounting."""
    source = _SyncSource(_LyingBytes(b"0123456789"))
    stream = _BoundedSyncRequestStream(source, max_request_bytes=4)

    with pytest.raises(EgressNotAllowedError) as caught:
        next(iter(stream))

    _assert_clean_denial(caught.value)
    assert source.closed is True


async def test_async_rejects_bytes_subclass_before_length_behavior() -> None:
    """Apply the exact-byte boundary to asynchronous request streams."""
    source = _AsyncSource(_LyingBytes(b"0123456789"))
    stream = _BoundedAsyncRequestStream(source, max_request_bytes=4)

    with pytest.raises(EgressNotAllowedError) as caught:
        await anext(stream.__aiter__())

    _assert_clean_denial(caught.value)
    assert source.closed is True


def test_sync_denial_contains_direct_custom_base_exception_cleanup() -> None:
    """Keep dependency cleanup BaseException detail behind generic denial."""
    source = _SyncSource(
        bytearray(b"unsafe"),
        _DirectCleanupBaseError("private synchronous cleanup detail"),
    )
    stream = _BoundedSyncRequestStream(source, max_request_bytes=4)

    with pytest.raises(EgressNotAllowedError) as caught:
        next(iter(stream))

    _assert_clean_denial(caught.value)
    assert source.closed is True


async def test_async_denial_contains_direct_custom_base_exception_cleanup() -> None:
    """Contain direct custom BaseException raised during async cleanup setup."""
    source = _AsyncSource(
        bytearray(b"unsafe"),
        _DirectCleanupBaseError("private asynchronous cleanup detail"),
    )
    stream = _BoundedAsyncRequestStream(source, max_request_bytes=4)

    with pytest.raises(EgressNotAllowedError) as caught:
        await anext(stream.__aiter__())

    _assert_clean_denial(caught.value)
    assert source.closed is True


@pytest.mark.parametrize("failure_type", [KeyboardInterrupt, SystemExit, GeneratorExit])
def test_sync_denial_preserves_interpreter_control_flow(
    failure_type: type[BaseException],
) -> None:
    """Never consume interpreter or process control flow during sync cleanup."""
    source = _SyncSource(bytearray(b"unsafe"), failure_type())
    stream = _BoundedSyncRequestStream(source, max_request_bytes=4)

    with pytest.raises(failure_type):
        next(iter(stream))

    assert source.closed is True


@pytest.mark.parametrize("failure_type", [KeyboardInterrupt, SystemExit, GeneratorExit])
async def test_async_denial_preserves_interpreter_control_flow(
    failure_type: type[BaseException],
) -> None:
    """Never consume interpreter or process control flow during async cleanup."""
    source = _AsyncSource(bytearray(b"unsafe"), failure_type())
    stream = _BoundedAsyncRequestStream(source, max_request_bytes=4)

    with pytest.raises(failure_type):
        await anext(stream.__aiter__())

    assert source.closed is True
