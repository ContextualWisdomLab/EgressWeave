"""Regression tests for non-leaking response-header denial cleanup."""

from __future__ import annotations

from types import SimpleNamespace

import httpx
import pytest

from egressweave import EGRESS_NOT_ALLOWED, EgressNotAllowedError, EgressPolicy
from egressweave.response_safety import _enforce_response_header_limits
from egressweave.sync_transport import _PinnedEgressTransport
from egressweave.transport import _PinnedEgressAsyncTransport
from egressweave.validation import _make_validated_egress_url


class _ExplodingSyncStream(httpx.SyncByteStream):
    """Raise caller-controlled text when a rejected sync response is closed."""

    def __iter__(self):
        """Yield one body chunk if the denial boundary is bypassed."""
        yield b"body"

    def close(self) -> None:
        """Raise an untrusted cleanup failure."""
        raise RuntimeError("secret synchronous cleanup failure")


class _ExplodingAsyncStream(httpx.AsyncByteStream):
    """Raise caller-controlled text when a rejected async response is closed."""

    async def __aiter__(self):
        """Yield one body chunk if the denial boundary is bypassed."""
        yield b"body"

    async def aclose(self) -> None:
        """Raise an untrusted asynchronous cleanup failure."""
        raise RuntimeError("secret asynchronous cleanup failure")


class _SyncPool:
    """Return one over-budget synchronous response without network I/O."""

    def __init__(self, stream: httpx.SyncByteStream) -> None:
        """Store the hostile source stream."""
        self._stream = stream

    def handle_request(self, request):
        """Return two fields when the policy permits only one."""
        return SimpleNamespace(
            status=200,
            headers=((b"x-one", b"1"), (b"x-two", b"2")),
            stream=self._stream,
            extensions={},
        )


class _AsyncPool:
    """Return one over-budget asynchronous response without network I/O."""

    def __init__(self, stream: httpx.AsyncByteStream) -> None:
        """Store the hostile asynchronous source stream."""
        self._stream = stream

    async def handle_async_request(self, request):
        """Return one field larger than the configured byte budget."""
        return SimpleNamespace(
            status=200,
            headers=((b"x", b"1234"),),
            stream=self._stream,
            extensions={},
        )


def _validated_result():
    """Return signed destination state without DNS I/O."""
    return _make_validated_egress_url(
        "https://api.example.com",
        "api.example.com",
        443,
        ("93.184.216.34",),
    )


def _request() -> httpx.Request:
    """Return a request matching the signed authority."""
    return httpx.Request("GET", "https://api.example.com/v1/models")


def _assert_generic_denial(error: EgressNotAllowedError) -> None:
    """Require the public error to retain no hostile exception context."""
    assert str(error) == EGRESS_NOT_ALLOWED
    assert error.__cause__ is None
    assert error.__context__ is None


def test_malformed_response_header_item_fails_generically() -> None:
    """Mask tuple-unpacking failures from malformed downstream metadata."""
    with pytest.raises(EgressNotAllowedError) as captured:
        _enforce_response_header_limits(
            ((b"only-name",),),  # type: ignore[arg-type]
            max_response_header_fields=10,
            max_response_header_bytes=1024,
        )

    _assert_generic_denial(captured.value)


def test_sync_header_denial_masks_response_cleanup_failure() -> None:
    """Keep arbitrary synchronous close failures behind the generic boundary."""
    transport = object.__new__(_PinnedEgressTransport)
    transport._validated = _validated_result()
    transport._policy = EgressPolicy.from_hosts(
        "api.example.com",
        max_response_header_fields=1,
    )
    transport._pool = _SyncPool(_ExplodingSyncStream())

    with pytest.raises(EgressNotAllowedError) as captured:
        transport.handle_request(_request())

    _assert_generic_denial(captured.value)


@pytest.mark.asyncio
async def test_async_header_denial_masks_response_cleanup_failure() -> None:
    """Keep arbitrary asynchronous close failures behind the generic boundary."""
    transport = object.__new__(_PinnedEgressAsyncTransport)
    transport._validated = _validated_result()
    transport._policy = EgressPolicy.from_hosts(
        "api.example.com",
        max_response_header_bytes=4,
    )
    transport._pool = _AsyncPool(_ExplodingAsyncStream())

    with pytest.raises(EgressNotAllowedError) as captured:
        await transport.handle_async_request(_request())

    _assert_generic_denial(captured.value)
