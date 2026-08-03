"""Complete branch coverage for the pinned HTTP transport."""

from __future__ import annotations

import asyncio
import socket
from collections.abc import AsyncIterator

import httpcore
import httpx
import pytest

from egressweave import EgressPolicy
from egressweave import validation as v
from egressweave.transport import (
    _PinnedEgressAsyncTransport,
    _PinnedEgressNetworkBackend,
    build_egress_http_client,
)

PUBLIC_ADDRESS = "93.184.216.34"
POLICY = EgressPolicy.from_hosts("api.openai.com")


class _FakeNetworkStream:
    """Minimal closable stream used by connection-race tests."""

    def __init__(self) -> None:
        self.closed = False

    async def aclose(self) -> None:
        """Record that the losing stream was closed."""
        self.closed = True


class _FakeNetworkBackend:
    """Record TCP and sleep calls made by the pinned backend."""

    def __init__(self, stream: _FakeNetworkStream) -> None:
        self.stream = stream
        self.connect_call = None
        self.sleep_seconds = None

    async def connect_tcp(self, host, port, **kwargs):
        """Return the configured stream and retain the canonical call."""
        self.connect_call = (host, port, kwargs)
        return self.stream

    async def sleep(self, seconds: float) -> None:
        """Record the delegated cooperative sleep."""
        self.sleep_seconds = seconds


class _AsyncBody:
    """Async response body compatible with httpcore's response stream."""

    def __init__(self, body: bytes = b"ok") -> None:
        self.body = body
        self.closed = False

    async def __aiter__(self) -> AsyncIterator[bytes]:
        """Yield the synthetic response body once."""
        yield self.body

    async def aclose(self) -> None:
        """Record response-stream closure."""
        self.closed = True


class _FakePool:
    """Capture the rewritten request and return a deterministic response."""

    def __init__(self) -> None:
        self.request = None
        self.body = _AsyncBody()
        self.closed = False

    async def handle_async_request(self, request: httpcore.Request) -> httpcore.Response:
        """Store the dispatched request and return a synthetic HTTP response."""
        self.request = request
        return httpcore.Response(
            201,
            headers=[(b"content-type", b"text/plain")],
            content=self.body,
            extensions={"synthetic": True},
        )

    async def aclose(self) -> None:
        """Record connection-pool closure."""
        self.closed = True


def _backend() -> _PinnedEgressNetworkBackend:
    """Build a policy-valid pinned backend without performing network I/O."""
    return _PinnedEgressNetworkBackend(
        "api.openai.com", 443, (PUBLIC_ADDRESS,), POLICY
    )


def _validated(monkeypatch: pytest.MonkeyPatch):
    """Return a signed validation result backed by deterministic DNS."""
    monkeypatch.setattr(
        v.socket,
        "getaddrinfo",
        lambda host, port, type=None: [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", (PUBLIC_ADDRESS, port))
        ],
    )
    result = v.validate_egress_url_details("https://api.openai.com", policy=POLICY)
    assert result is not None
    return result


async def test_connect_one_pinned_address_and_delegate_sleep() -> None:
    backend = _backend()
    stream = _FakeNetworkStream()
    fake_backend = _FakeNetworkBackend(stream)
    backend._backend = fake_backend

    result = await backend._connect_validated_ip_address(
        PUBLIC_ADDRESS,
        443,
        timeout=2.0,
        local_address="0.0.0.0",
        socket_options=[(1, 2, 3)],
    )
    await backend.sleep(0.25)

    assert result is stream
    assert fake_backend.connect_call == (
        PUBLIC_ADDRESS,
        443,
        {
            "timeout": 2.0,
            "local_address": "0.0.0.0",
            "socket_options": [(1, 2, 3)],
        },
    )
    assert fake_backend.sleep_seconds == 0.25


async def test_cancel_and_wait_tasks_handles_empty_and_pending_sets() -> None:
    backend = _backend()
    blocker = asyncio.Event()

    async def wait_forever() -> None:
        await blocker.wait()

    task = asyncio.create_task(wait_forever())
    await asyncio.sleep(0)

    await backend._cancel_and_wait_tasks({task})
    await backend._cancel_and_wait_tasks(set())

    assert task.cancelled()


async def test_wait_for_first_success_closes_simultaneous_extra_stream() -> None:
    backend = _backend()
    streams = [_FakeNetworkStream(), _FakeNetworkStream()]

    async def return_stream(stream: _FakeNetworkStream) -> _FakeNetworkStream:
        return stream

    tasks = {asyncio.create_task(return_stream(stream)) for stream in streams}
    await asyncio.sleep(0)

    selected, last_error = await backend._wait_for_first_successful_stream(tasks)

    assert selected in streams
    assert last_error is None
    assert sum(stream.closed for stream in streams) == 1
    assert selected is not None and selected.closed is False


async def test_wait_for_first_success_continues_after_failed_address() -> None:
    backend = _backend()
    stream = _FakeNetworkStream()

    async def fail_immediately():
        raise RuntimeError("first address failed")

    async def succeed_later():
        await asyncio.sleep(0.01)
        return stream

    tasks = {
        asyncio.create_task(fail_immediately()),
        asyncio.create_task(succeed_later()),
    }

    selected, last_error = await backend._wait_for_first_successful_stream(tasks)

    assert selected is stream
    assert isinstance(last_error, RuntimeError)


async def test_wait_for_first_success_returns_last_error_when_all_fail() -> None:
    backend = _backend()

    async def fail():
        raise OSError("all addresses failed")

    tasks = {asyncio.create_task(fail())}
    selected, last_error = await backend._wait_for_first_successful_stream(tasks)

    assert selected is None
    assert isinstance(last_error, OSError)


@pytest.mark.parametrize(
    ("wait_result", "expected"),
    [
        ((_FakeNetworkStream(), None), "success"),
        ((None, RuntimeError("connect failed")), RuntimeError),
        ((None, None), OSError),
    ],
    ids=["success", "last-error", "generic-error"],
)
async def test_connect_tcp_handles_every_race_outcome(monkeypatch, wait_result, expected):
    backend = _backend()
    pending = asyncio.Event()

    async def block_connect(*args, **kwargs):
        await pending.wait()

    async def return_outcome(tasks):
        return wait_result

    monkeypatch.setattr(backend, "_connect_validated_ip_address", block_connect)
    monkeypatch.setattr(backend, "_wait_for_first_successful_stream", return_outcome)

    if expected == "success":
        assert await backend.connect_tcp("api.openai.com", 443) is wait_result[0]
    else:
        with pytest.raises(expected):
            await backend.connect_tcp("api.openai.com", 443)


async def test_transport_rewrites_host_header_and_returns_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    transport = object.__new__(_PinnedEgressAsyncTransport)
    transport._validated = _validated(monkeypatch)
    pool = _FakePool()
    transport._pool = pool
    request = httpx.Request(
        "POST",
        "https://api.openai.com/v1/models?after=cursor",
        headers={"Host": "spoofed.example", "X-Test": "yes"},
        content=b"request-body",
    )

    response = await transport.handle_async_request(request)

    assert response.status_code == 201
    assert await response.aread() == b"ok"
    assert response.extensions["synthetic"] is True
    assert pool.request is not None
    assert pool.request.url.host == b"api.openai.com"
    assert pool.request.url.port == 443
    assert pool.request.url.target == b"/v1/models?after=cursor"
    headers = {key.lower(): value for key, value in pool.request.headers}
    assert headers[b"host"] == b"api.openai.com"
    assert headers[b"x-test"] == b"yes"
    await response.aclose()
    assert pool.body.closed is True


async def test_transport_close_delegates_to_pool(monkeypatch: pytest.MonkeyPatch) -> None:
    transport = object.__new__(_PinnedEgressAsyncTransport)
    transport._validated = _validated(monkeypatch)
    pool = _FakePool()
    transport._pool = pool

    await transport.aclose()

    assert pool.closed is True


async def test_build_egress_client_covers_empty_and_valid_urls(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    normalized, plain_client = await build_egress_http_client(None, policy=POLICY)
    assert normalized is None
    assert plain_client.follow_redirects is False
    await plain_client.aclose()

    _validated(monkeypatch)
    normalized, pinned_client = await build_egress_http_client(
        "https://api.openai.com/v1", policy=POLICY
    )
    assert normalized == "https://api.openai.com/v1"
    assert isinstance(pinned_client._transport, _PinnedEgressAsyncTransport)
    await pinned_client.aclose()
