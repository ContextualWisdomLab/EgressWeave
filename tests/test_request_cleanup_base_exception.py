"""Regressions for request cleanup failures outside the Exception hierarchy."""

from __future__ import annotations

import httpx
import pytest

from egressweave import EgressNotAllowedError
from egressweave.request_body_safety import (
    _BoundedAsyncRequestStream,
    _BoundedSyncRequestStream,
)


class _DirectCleanupBaseError(BaseException):
    """Model a dependency-controlled failure outside the ``Exception`` tree."""


class _BaseExceptionCleanupSyncRequestStream(httpx.SyncByteStream):
    """Raise a configured ``BaseException`` when denied sync cleanup is invoked."""

    def __init__(
        self, chunk: object, *, failure: BaseException | None = None
    ) -> None:
        """Store one unsafe chunk, cleanup failure, and attempt state."""
        self._chunk = chunk
        self._failure = failure or _DirectCleanupBaseError(
            "private direct request cleanup failure"
        )
        self.closed = False

    def __iter__(self):
        """Yield the configured unsafe chunk before policy cleanup runs."""
        yield self._chunk

    def close(self) -> None:
        """Raise the configured base exception after recording cleanup."""
        self.closed = True
        raise self._failure


class _BaseExceptionCleanupAsyncRequestStream(httpx.AsyncByteStream):
    """Raise a configured ``BaseException`` while denied cleanup is invoked."""

    def __init__(
        self, chunk: object, *, failure: BaseException | None = None
    ) -> None:
        """Store one unsafe chunk, cleanup failure, and attempt state."""
        self._chunk = chunk
        self._failure = failure or _DirectCleanupBaseError(
            "private direct request cleanup failure"
        )
        self.closed = False

    async def __aiter__(self):
        """Yield the configured unsafe chunk before policy cleanup runs."""
        yield self._chunk

    def aclose(self):
        """Raise the configured base exception before returning an awaitable."""
        self.closed = True
        raise self._failure


def _assert_clean_policy_denial(error: EgressNotAllowedError) -> None:
    """Require a generic denial with no retained cleanup exception provenance."""
    assert str(error) == "egress URL is not allowed"
    assert error.__context__ is None
    assert error.__cause__ is None


def test_sync_policy_denial_masks_direct_base_exception_cleanup() -> None:
    """Keep a direct custom ``BaseException`` behind the generic denial."""
    source = _BaseExceptionCleanupSyncRequestStream(bytearray(b"abc"))
    stream = _BoundedSyncRequestStream(source, max_request_bytes=4)

    with pytest.raises(EgressNotAllowedError) as exc_info:
        next(iter(stream))

    _assert_clean_policy_denial(exc_info.value)
    assert source.closed is True


async def test_async_policy_denial_masks_direct_base_exception_cleanup() -> None:
    """Keep a direct custom ``BaseException`` from async setup behind denial."""
    source = _BaseExceptionCleanupAsyncRequestStream(bytearray(b"abc"))
    stream = _BoundedAsyncRequestStream(source, max_request_bytes=4)

    with pytest.raises(EgressNotAllowedError) as exc_info:
        await anext(stream.__aiter__())

    _assert_clean_policy_denial(exc_info.value)
    assert source.closed is True


@pytest.mark.parametrize("failure_type", [KeyboardInterrupt, SystemExit, GeneratorExit])
def test_sync_policy_denial_preserves_cleanup_control_flow(
    failure_type: type[BaseException],
) -> None:
    """Propagate interpreter control flow raised by direct sync cleanup."""
    source = _BaseExceptionCleanupSyncRequestStream(
        bytearray(b"abc"), failure=failure_type("operator control flow")
    )
    stream = _BoundedSyncRequestStream(source, max_request_bytes=4)

    with pytest.raises(failure_type):
        next(iter(stream))

    assert source.closed is True


@pytest.mark.parametrize("failure_type", [KeyboardInterrupt, SystemExit, GeneratorExit])
async def test_async_policy_denial_preserves_cleanup_control_flow(
    failure_type: type[BaseException],
) -> None:
    """Propagate interpreter control flow raised during async cleanup setup."""
    source = _BaseExceptionCleanupAsyncRequestStream(
        bytearray(b"abc"), failure=failure_type("operator control flow")
    )
    stream = _BoundedAsyncRequestStream(source, max_request_bytes=4)

    with pytest.raises(failure_type):
        await anext(stream.__aiter__())

    assert source.closed is True
