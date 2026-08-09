"""Regression contracts for caller-visible response extension capabilities."""

from __future__ import annotations

from dataclasses import dataclass

import httpx
import pytest

from egressweave import (
    EgressNotAllowedError,
    EgressPolicy,
    sync_transport,
    transport,
    validation,
)

PUBLIC_ADDRESS = "93.184.216.34"
POLICY = EgressPolicy.from_hosts("api.example.com")
VALIDATED = validation._make_validated_egress_url(
    "https://api.example.com",
    "api.example.com",
    443,
    (PUBLIC_ADDRESS,),
)


class _SyncCoreStream:
    """Minimal synchronous HTTP-core stream for transport boundary tests."""

    def __init__(self) -> None:
        """Start with an open synthetic stream."""
        self.closed = False

    def __iter__(self):
        """Yield one ordinary response body chunk."""
        yield b"ok"

    def close(self) -> None:
        """Record deterministic stream closure."""
        self.closed = True


class _AsyncCoreStream:
    """Minimal asynchronous HTTP-core stream for transport boundary tests."""

    def __init__(self) -> None:
        """Start with an open synthetic async stream."""
        self.closed = False

    async def __aiter__(self):
        """Yield one ordinary response body chunk."""
        yield b"ok"

    async def aclose(self) -> None:
        """Record deterministic async stream closure."""
        self.closed = True


class _HostileExtensionBytes(bytes):
    """Represent non-inert metadata that must never reach the public response."""

    def __repr__(self) -> str:
        """Fail if caller-visible handling executes subclass representation."""
        raise AssertionError("response extension byte subclass behavior executed")


@dataclass
class _CoreResponse:
    """Small response object matching the attributes consumed by transports."""

    stream: object
    status: int = 200
    headers: tuple[tuple[bytes, bytes], ...] = ((b"content-length", b"2"),)
    extensions: dict[str, object] | None = None

    def __post_init__(self) -> None:
        """Provide ordinary metadata plus one raw transport capability."""
        if self.extensions is None:
            self.extensions = {
                "http_version": b"HTTP/1.1",
                "reason_phrase": b"OK",
                "network_stream": object(),
            }


class _SyncPool:
    """Return one synthetic response without touching the network."""

    def handle_request(self, request):
        """Return the configured core response."""
        return _CoreResponse(_SyncCoreStream())

    def close(self) -> None:
        """Close the synthetic pool."""


class _AsyncPool:
    """Return one synthetic async response without touching the network."""

    async def handle_async_request(self, request):
        """Return the configured core response."""
        return _CoreResponse(_AsyncCoreStream())

    async def aclose(self) -> None:
        """Close the synthetic pool."""


class _SyncExtensionPool:
    """Return caller-selected low-level response extension metadata."""

    def __init__(self, extensions: dict[str, object]) -> None:
        """Store the extensions and one inspectable response stream."""
        self._extensions = extensions
        self.stream = _SyncCoreStream()

    def handle_request(self, request):
        """Return one response carrying the configured extensions."""
        return _CoreResponse(self.stream, extensions=self._extensions)

    def close(self) -> None:
        """Close the synthetic pool."""


class _AsyncExtensionPool:
    """Return caller-selected async low-level response extension metadata."""

    def __init__(self, extensions: dict[str, object]) -> None:
        """Store the extensions and one inspectable async response stream."""
        self._extensions = extensions
        self.stream = _AsyncCoreStream()

    async def handle_async_request(self, request):
        """Return one response carrying the configured extensions."""
        return _CoreResponse(self.stream, extensions=self._extensions)

    async def aclose(self) -> None:
        """Close the synthetic pool."""


def test_sync_response_hides_raw_network_stream_extension() -> None:
    """Expose only reviewed inert metadata through a synchronous response."""
    pinned = sync_transport._PinnedEgressTransport(VALIDATED, POLICY)
    pinned._pool = _SyncPool()

    response = pinned.handle_request(httpx.Request("GET", VALIDATED.normalized_url))

    assert response.extensions == {
        "http_version": b"HTTP/1.1",
        "reason_phrase": b"OK",
    }


async def test_async_response_hides_raw_network_stream_extension() -> None:
    """Expose only reviewed inert metadata through an asynchronous response."""
    pinned = transport._PinnedEgressAsyncTransport(VALIDATED, POLICY)
    pinned._pool = _AsyncPool()

    response = await pinned.handle_async_request(
        httpx.Request("GET", VALIDATED.normalized_url)
    )

    assert response.extensions == {
        "http_version": b"HTTP/1.1",
        "reason_phrase": b"OK",
    }


@pytest.mark.parametrize(
    "extensions",
    (
        {"http_version": object()},
        {"reason_phrase": _HostileExtensionBytes(b"OK")},
    ),
)
def test_sync_response_rejects_non_exact_public_extension_values(
    extensions: dict[str, object],
) -> None:
    """Fail closed and release the source instead of exposing arbitrary objects."""
    pinned = sync_transport._PinnedEgressTransport(VALIDATED, POLICY)
    pool = _SyncExtensionPool(extensions)
    pinned._pool = pool

    with pytest.raises(EgressNotAllowedError, match="^egress URL is not allowed$"):
        pinned.handle_request(httpx.Request("GET", VALIDATED.normalized_url))

    assert pool.stream.closed is True


@pytest.mark.parametrize(
    "extensions",
    (
        {"http_version": object()},
        {"reason_phrase": _HostileExtensionBytes(b"OK")},
    ),
)
async def test_async_response_rejects_non_exact_public_extension_values(
    extensions: dict[str, object],
) -> None:
    """Apply the same inert-metadata and cleanup boundary asynchronously."""
    pinned = transport._PinnedEgressAsyncTransport(VALIDATED, POLICY)
    pool = _AsyncExtensionPool(extensions)
    pinned._pool = pool

    with pytest.raises(EgressNotAllowedError, match="^egress URL is not allowed$"):
        await pinned.handle_async_request(
            httpx.Request("GET", VALIDATED.normalized_url)
        )

    assert pool.stream.closed is True
