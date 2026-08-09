"""Regression contracts for caller-visible response extension capabilities."""

from __future__ import annotations

from dataclasses import dataclass

import httpx
import pytest

from egressweave import (
    EgressNotAllowedError,
    EgressPolicy,
    response_safety,
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


class _HostileExtensionDict(dict):
    """Represent a mapping subclass whose behavior must never be trusted."""

    def __contains__(self, key: object) -> bool:
        """Fail if extension filtering invokes subclass membership behavior."""
        raise AssertionError("response extension mapping behavior executed")


class _HostileExtensionKey:
    """Collide with one reviewed key and fail if dictionary equality executes."""

    def __hash__(self) -> int:
        """Return the same hash as the reviewed HTTP-version extension key."""
        return hash("http_version")

    def __eq__(self, other: object) -> bool:
        """Expose exact-dict lookup of dependency-controlled key behavior."""
        raise RuntimeError("private response extension key comparison")


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

    def __init__(
        self,
        extensions: dict[str, object],
        *,
        status: int = 200,
        headers: tuple[tuple[bytes, bytes], ...] = ((b"content-length", b"2"),),
    ) -> None:
        """Store extensions, response metadata, and one inspectable stream."""
        self._extensions = extensions
        self._status = status
        self._headers = headers
        self.stream = _SyncCoreStream()

    def handle_request(self, request):
        """Return one response carrying the configured extensions."""
        return _CoreResponse(
            self.stream,
            status=self._status,
            headers=self._headers,
            extensions=self._extensions,
        )

    def close(self) -> None:
        """Close the synthetic pool."""


class _AsyncExtensionPool:
    """Return caller-selected async low-level response extension metadata."""

    def __init__(
        self,
        extensions: dict[str, object],
        *,
        status: int = 200,
        headers: tuple[tuple[bytes, bytes], ...] = ((b"content-length", b"2"),),
    ) -> None:
        """Store extensions, response metadata, and one inspectable async stream."""
        self._extensions = extensions
        self._status = status
        self._headers = headers
        self.stream = _AsyncCoreStream()

    async def handle_async_request(self, request):
        """Return one response carrying the configured extensions."""
        return _CoreResponse(
            self.stream,
            status=self._status,
            headers=self._headers,
            extensions=self._extensions,
        )

    async def aclose(self) -> None:
        """Close the synthetic pool."""


def test_response_extension_container_must_be_exact_dict() -> None:
    """Reject mapping subclasses before any dependency-controlled method runs."""
    extensions = _HostileExtensionDict(http_version=b"HTTP/1.1")

    with pytest.raises(EgressNotAllowedError, match="^egress URL is not allowed$"):
        response_safety._select_public_response_extensions(extensions)


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


def test_sync_bodyless_response_hides_raw_network_stream_extension() -> None:
    """Apply the same extension boundary to an RFC-bodyless response."""
    pinned = sync_transport._PinnedEgressTransport(VALIDATED, POLICY)
    pool = _SyncExtensionPool(
        {
            "http_version": b"HTTP/1.1",
            "reason_phrase": b"No Content",
            "network_stream": object(),
        },
        status=204,
        headers=(),
    )
    pinned._pool = pool

    response = pinned.handle_request(httpx.Request("GET", VALIDATED.normalized_url))

    assert response.status_code == 204
    assert response.extensions == {
        "http_version": b"HTTP/1.1",
        "reason_phrase": b"No Content",
    }


async def test_async_bodyless_response_hides_raw_network_stream_extension() -> None:
    """Apply the same extension boundary to an async RFC-bodyless response."""
    pinned = transport._PinnedEgressAsyncTransport(VALIDATED, POLICY)
    pool = _AsyncExtensionPool(
        {
            "http_version": b"HTTP/1.1",
            "reason_phrase": b"No Content",
            "network_stream": object(),
        },
        status=204,
        headers=(),
    )
    pinned._pool = pool

    response = await pinned.handle_async_request(
        httpx.Request("GET", VALIDATED.normalized_url)
    )

    assert response.status_code == 204
    assert response.extensions == {
        "http_version": b"HTTP/1.1",
        "reason_phrase": b"No Content",
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


def test_sync_response_rejects_hostile_exact_dict_key_and_closes_source() -> None:
    """Contain exact-dict key behavior inside the synchronous denial boundary."""
    pinned = sync_transport._PinnedEgressTransport(VALIDATED, POLICY)
    pool = _SyncExtensionPool({_HostileExtensionKey(): b"unreachable"})
    pinned._pool = pool

    with pytest.raises(EgressNotAllowedError, match="^egress URL is not allowed$") as caught:
        pinned.handle_request(httpx.Request("GET", VALIDATED.normalized_url))

    assert pool.stream.closed is True
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None


async def test_async_response_rejects_hostile_exact_dict_key_and_closes_source() -> None:
    """Contain exact-dict key behavior inside the asynchronous denial boundary."""
    pinned = transport._PinnedEgressAsyncTransport(VALIDATED, POLICY)
    pool = _AsyncExtensionPool({_HostileExtensionKey(): b"unreachable"})
    pinned._pool = pool

    with pytest.raises(EgressNotAllowedError, match="^egress URL is not allowed$") as caught:
        await pinned.handle_async_request(
            httpx.Request("GET", VALIDATED.normalized_url)
        )

    assert pool.stream.closed is True
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None
