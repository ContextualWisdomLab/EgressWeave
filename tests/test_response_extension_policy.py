"""Regression contracts for caller-visible response extension capabilities."""

from __future__ import annotations

from dataclasses import dataclass

import httpx

from egressweave import EgressPolicy
from egressweave import sync_transport, transport, validation

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

    def __iter__(self):
        """Yield one ordinary response body chunk."""
        yield b"ok"

    def close(self) -> None:
        """Close the synthetic stream."""


class _AsyncCoreStream:
    """Minimal asynchronous HTTP-core stream for transport boundary tests."""

    async def __aiter__(self):
        """Yield one ordinary response body chunk."""
        yield b"ok"

    async def aclose(self) -> None:
        """Close the synthetic stream."""


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
