"""Public-client regression contracts for safe framework request defaults."""

from __future__ import annotations

import httpcore

from egressweave import (
    EgressPolicy,
    build_pinned_https_async_client,
    build_pinned_https_client,
    validate_egress_url_details,
)
from egressweave import validation as v

POLICY = EgressPolicy.from_hosts("api.openai.com")


def _validated_result(monkeypatch):
    """Return deterministic public validation state without external DNS."""

    def fake_getaddrinfo(host, port, type=None):
        return [(2, 1, 6, "", ("93.184.216.34", port))]

    monkeypatch.setattr(v.socket, "getaddrinfo", fake_getaddrinfo)
    validated = validate_egress_url_details(
        "https://api.openai.com", policy=POLICY
    )
    assert validated is not None
    return validated


class _SyncRecordingPool:
    """Record the exact synchronous request reaching the pinned pool."""

    def __init__(self) -> None:
        self.requests = []
        self.closed = False

    def handle_request(self, request):
        self.requests.append(request)
        return httpcore.Response(204, headers=[], content=b"")

    def close(self) -> None:
        self.closed = True


class _AsyncRecordingPool:
    """Record the exact asynchronous request reaching the pinned pool."""

    def __init__(self) -> None:
        self.requests = []
        self.closed = False

    async def handle_async_request(self, request):
        self.requests.append(request)

        async def empty_content():
            if False:  # pragma: no cover - async iterator shape only
                yield b""

        return httpcore.Response(204, headers=[], content=empty_content())

    async def aclose(self) -> None:
        self.closed = True


def _assert_no_hop_by_hop_defaults(request) -> None:
    """Require the final pinned request to contain no ambient connection controls."""
    names = {name.lower() for name, _ in request.headers}
    assert b"connection" not in names
    assert b"keep-alive" not in names
    assert b"proxy-authenticate" not in names
    assert b"proxy-authorization" not in names
    assert b"proxy-connection" not in names
    assert b"upgrade" not in names


def test_sync_public_client_dispatches_ordinary_get_without_ambient_hop_by_hop(
    monkeypatch,
) -> None:
    """A caller should not need to delete HTTPX defaults before a safe GET."""
    validated = _validated_result(monkeypatch)
    pool = _SyncRecordingPool()

    with build_pinned_https_client(validated, policy=POLICY) as client:
        client._transport._pool = pool
        response = client.get("https://api.openai.com/v1/models")

    assert response.status_code == 204
    assert len(pool.requests) == 1
    _assert_no_hop_by_hop_defaults(pool.requests[0])
    assert pool.closed is True


async def test_async_public_client_dispatches_ordinary_get_without_ambient_hop_by_hop(
    monkeypatch,
) -> None:
    """The async public builder must normalize the same framework defaults."""
    validated = _validated_result(monkeypatch)
    pool = _AsyncRecordingPool()

    async with build_pinned_https_async_client(validated, policy=POLICY) as client:
        client._transport._pool = pool
        response = await client.get("https://api.openai.com/v1/models")

    assert response.status_code == 204
    assert len(pool.requests) == 1
    _assert_no_hop_by_hop_defaults(pool.requests[0])
    assert pool.closed is True
