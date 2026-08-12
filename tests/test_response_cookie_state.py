"""Security contracts for response-driven cookie state in pinned clients."""

from __future__ import annotations

import httpcore
import pytest

from egressweave import (
    EgressNotAllowedError,
    EgressPolicy,
    build_pinned_https_async_client,
    build_pinned_https_client,
    validate_egress_url_details,
)
from egressweave import validation as v

POLICY = EgressPolicy.from_hosts("api.openai.com")
_SERVER_COOKIE = b"session=server; Domain=.openai.com; Path=/"


def _validated_result(monkeypatch):
    """Return one deterministic public validated authority without public DNS."""

    def fake_getaddrinfo(host, port, type=None):
        return [(2, 1, 6, "", ("93.184.216.34", port))]

    monkeypatch.setattr(v.socket, "getaddrinfo", fake_getaddrinfo)
    validated = validate_egress_url_details(
        "https://api.openai.com", policy=POLICY
    )
    assert validated is not None
    return validated


def _header_value(request, name: bytes) -> bytes | None:
    """Return one recorded HTTP core request header by lowercase name."""
    return {key.lower(): value for key, value in request.headers}.get(name.lower())


class _SyncCookiePool:
    """Return one response cookie and record every synchronous outbound request."""

    def __init__(self) -> None:
        self.requests = []
        self.closed = False

    def handle_request(self, request):
        self.requests.append(request)
        headers = [(b"set-cookie", _SERVER_COOKIE)] if len(self.requests) == 1 else []
        return httpcore.Response(204, headers=headers, content=b"")

    def close(self) -> None:
        self.closed = True


class _AsyncCookiePool:
    """Return one response cookie and record every asynchronous outbound request."""

    def __init__(self) -> None:
        self.requests = []
        self.closed = False

    async def handle_async_request(self, request):
        self.requests.append(request)
        headers = [(b"set-cookie", _SERVER_COOKIE)] if len(self.requests) == 1 else []

        async def empty_content():
            if False:  # pragma: no cover - required async-iterator shape only
                yield b""

        return httpcore.Response(204, headers=headers, content=empty_content())

    async def aclose(self) -> None:
        self.closed = True


def test_sync_client_does_not_replay_response_cookie(monkeypatch) -> None:
    """A response cookie must stay visible without becoming later request state."""
    validated = _validated_result(monkeypatch)
    pool = _SyncCookiePool()

    with build_pinned_https_client(validated, policy=POLICY) as client:
        client._transport._pool = pool
        first = client.get("https://api.openai.com/first")
        assert first.headers["set-cookie"].startswith("session=server")

        client.get("https://api.openai.com/second")

    assert len(pool.requests) == 2
    assert _header_value(pool.requests[1], b"cookie") is None
    assert pool.closed is True


async def test_async_client_does_not_replay_response_cookie(monkeypatch) -> None:
    """Async response cookies must not silently become later request metadata."""
    validated = _validated_result(monkeypatch)
    pool = _AsyncCookiePool()

    async with build_pinned_https_async_client(validated, policy=POLICY) as client:
        client._transport._pool = pool
        first = await client.get("https://api.openai.com/first")
        assert first.headers["set-cookie"].startswith("session=server")

        await client.get("https://api.openai.com/second")

    assert len(pool.requests) == 2
    assert _header_value(pool.requests[1], b"cookie") is None
    assert pool.closed is True


def test_sync_client_preserves_explicit_host_owned_cookie_state(monkeypatch) -> None:
    """Callers may still opt into explicit same-authority cookie credentials."""
    validated = _validated_result(monkeypatch)
    pool = _SyncCookiePool()

    with build_pinned_https_client(validated, policy=POLICY) as client:
        client._transport._pool = pool
        client.cookies.set(
            "host_session",
            "caller",
            domain="api.openai.com",
            path="/",
        )
        client.get("https://api.openai.com/explicit")

    cookie = _header_value(pool.requests[0], b"cookie")
    assert cookie is not None
    assert b"host_session=caller" in cookie


def test_sync_client_keeps_exact_authority_denial_after_response_cookie(monkeypatch) -> None:
    """Cookie-domain metadata cannot widen the validated transport authority."""
    validated = _validated_result(monkeypatch)
    pool = _SyncCookiePool()

    with build_pinned_https_client(validated, policy=POLICY) as client:
        client._transport._pool = pool
        client.get("https://api.openai.com/first")

        with pytest.raises(
            EgressNotAllowedError, match="^egress URL is not allowed$"
        ):
            client.get("https://other.openai.com/second")

    assert len(pool.requests) == 1
