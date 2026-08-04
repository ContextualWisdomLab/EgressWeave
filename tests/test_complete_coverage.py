"""Deterministic coverage for defensive policy, resolver, and transport branches."""

from __future__ import annotations

import asyncio
from collections.abc import Iterable

import pytest

from egressweave import (
    EgressNotAllowedError,
    EgressPolicy,
    build_egress_http_client,
    build_egress_sync_client,
    request_safety,
    validate_egress_url_async,
    validate_egress_url_details_async,
    validation,
)
from egressweave import transport as async_transport
from egressweave.sync_transport import _PinnedEgressSyncNetworkBackend
from egressweave.transport import _PinnedEgressNetworkBackend

PUBLIC_ADDRESS = "93.184.216.34"
SECOND_PUBLIC_ADDRESS = "93.184.216.35"
POLICY = EgressPolicy.from_hosts("api.example.com")


class _FakeSemaphore:
    """Record bounded-resolver slot acquisition and release behavior."""

    def __init__(self, acquired: bool = True) -> None:
        self.acquired = acquired
        self.release_count = 0

    def acquire(self, *, timeout: float) -> bool:
        """Return the configured acquisition result."""
        assert timeout > 0
        return self.acquired

    def release(self) -> None:
        """Record one slot release."""
        self.release_count += 1


class _FakeClock:
    """Return a deterministic sequence of event-loop timestamps."""

    def __init__(self, *timestamps: float) -> None:
        self._timestamps = list(timestamps)
        self._last = timestamps[-1]

    def time(self) -> float:
        """Return the next timestamp, then repeat the final timestamp."""
        if self._timestamps:
            self._last = self._timestamps.pop(0)
        return self._last


class _AsyncStream:
    """Minimal asynchronous network stream with observable closure."""

    def __init__(self) -> None:
        self.closed = False

    async def aclose(self) -> None:
        """Record closure of a losing connection attempt."""
        self.closed = True


class _SyncBackend:
    """Configurable synchronous backend used to avoid real network access."""

    def __init__(self, outcomes: Iterable[object]) -> None:
        self.outcomes = iter(outcomes)
        self.calls: list[tuple[str, int, dict[str, object]]] = []

    def connect_tcp(self, host: str, port: int, **kwargs):
        """Return or raise the next configured connection outcome."""
        self.calls.append((host, port, kwargs))
        outcome = next(self.outcomes)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


def test_direct_policy_strings_cover_projection_normalization() -> None:
    """Normalize direct dataclass strings for ports and methods."""
    policy = EgressPolicy(
        allowed_hosts="api.example.com",
        allowed_ports="443",
        allowed_methods="get, head",
    )

    assert policy.allowed_authorities == frozenset({("api.example.com", 443)})
    assert policy.allowed_methods == frozenset({"GET", "HEAD"})


def test_request_safety_rejects_invalid_sni_extension_types() -> None:
    """Reject non-ASCII bytes and nontextual TLS server-name overrides."""
    for server_name in (b"\xff.example", 42):
        with pytest.raises(EgressNotAllowedError):
            request_safety._bind_validated_tls_server_name(
                {"sni_hostname": server_name}, "api.example.com"
            )


def test_validation_helpers_cover_ip_and_invalid_address_paths() -> None:
    """Exercise canonical IP detection and invalid address rejection."""
    assert validation._is_ip_literal("127.0.0.1") is True
    with pytest.raises(EgressNotAllowedError):
        validation._validate_global_address("not-an-address", POLICY)


def test_blocking_resolver_rejects_empty_and_deduplicates_results(monkeypatch) -> None:
    """Cover empty DNS answers and duplicate canonical addresses."""
    monkeypatch.setattr(validation.socket, "getaddrinfo", lambda *args, **kwargs: [])
    with pytest.raises(EgressNotAllowedError):
        validation._resolve_all_global_addresses_blocking(
            "api.example.com", 443, POLICY
        )

    monkeypatch.setattr(
        validation.socket,
        "getaddrinfo",
        lambda *args, **kwargs: [
            (2, 1, 6, "", (PUBLIC_ADDRESS, 443)),
            (2, 1, 6, "", (PUBLIC_ADDRESS, 443)),
        ],
    )
    assert validation._resolve_all_global_addresses_blocking(
        "api.example.com", 443, POLICY
    ) == (PUBLIC_ADDRESS,)


def test_bounded_resolver_rejects_slot_exhaustion(monkeypatch) -> None:
    """Fail closed when the bounded DNS worker pool has no available slot."""
    semaphore = _FakeSemaphore(acquired=False)
    monkeypatch.setattr(validation, "_DNS_RESOLUTION_SLOTS", semaphore)

    with pytest.raises(EgressNotAllowedError):
        validation._resolve_all_global_addresses("api.example.com", 443, POLICY)
    assert semaphore.release_count == 0


def test_bounded_resolver_rejects_budget_exhaustion_before_worker_start(
    monkeypatch,
) -> None:
    """Release an acquired slot when the deadline expires before thread start."""
    semaphore = _FakeSemaphore()
    timestamps = iter((0.0, 10.0))
    monkeypatch.setattr(validation, "_DNS_RESOLUTION_SLOTS", semaphore)
    monkeypatch.setattr(validation.time, "monotonic", lambda: next(timestamps))

    with pytest.raises(EgressNotAllowedError):
        validation._resolve_all_global_addresses("api.example.com", 443, POLICY)
    assert semaphore.release_count == 1


def test_bounded_resolver_wraps_worker_start_failure(monkeypatch) -> None:
    """Release the slot and hide a platform thread-start failure."""
    semaphore = _FakeSemaphore()

    class _BrokenThread:
        def start(self) -> None:
            raise RuntimeError("synthetic thread failure")

    monkeypatch.setattr(validation, "_DNS_RESOLUTION_SLOTS", semaphore)
    monkeypatch.setattr(validation.threading, "Thread", lambda **kwargs: _BrokenThread())

    with pytest.raises(EgressNotAllowedError):
        validation._resolve_all_global_addresses("api.example.com", 443, POLICY)
    assert semaphore.release_count == 1


@pytest.mark.parametrize(
    "outcome",
    [
        EgressNotAllowedError("egress URL is not allowed"),
        RuntimeError("backend detail"),
        None,
    ],
    ids=["policy-error", "unexpected-error", "missing-addresses"],
)
def test_bounded_resolver_normalizes_worker_outcomes(monkeypatch, outcome) -> None:
    """Preserve only the generic error boundary for worker outcomes."""
    if isinstance(outcome, Exception):

        def resolve(*args, **kwargs):
            raise outcome

    else:

        def resolve(*args, **kwargs):
            return None

    monkeypatch.setattr(validation, "_resolve_all_global_addresses_blocking", resolve)

    with pytest.raises(EgressNotAllowedError, match="^egress URL is not allowed$"):
        validation._resolve_all_global_addresses("api.example.com", 443, POLICY)


def test_url_parser_wraps_structural_parse_errors() -> None:
    """Keep malformed IPv6 authority details behind the generic error."""
    with pytest.raises(EgressNotAllowedError):
        validation._parse_and_validate_candidate_url("https://[::1")


def test_local_url_requires_allow_local_even_when_authority_is_listed() -> None:
    """Require the explicit local-address escape hatch for localhost URLs."""
    policy = EgressPolicy.from_hosts("localhost")
    with pytest.raises(EgressNotAllowedError):
        validation._normalize_egress_url("https://localhost", policy)


def test_ip_literal_defense_remains_after_authority_authorization() -> None:
    """Reject an IP literal even if a malicious policy double claims the pair."""

    class _PermissivePolicy:
        allowed_authorities = frozenset({("127.0.0.1", 443)})

        def allows_authority(self, hostname: str, port: int) -> bool:
            return True

    with pytest.raises(EgressNotAllowedError):
        validation._validate_remote_authority_is_allowed(
            "127.0.0.1", 443, _PermissivePolicy()
        )


def test_signed_but_noncanonical_result_is_rejected() -> None:
    """Reject signed state whose URL does not equal its normalized form."""
    result = validation._make_validated_egress_url(
        "https://API.Example.com",
        "api.example.com",
        443,
        (PUBLIC_ADDRESS,),
    )
    with pytest.raises(EgressNotAllowedError):
        validation._revalidate_pinned_egress_url(result, POLICY)


async def test_empty_async_validation_paths_return_none() -> None:
    """Cover both asynchronous convenience functions for absent configuration."""
    assert await validate_egress_url_details_async(None, policy=POLICY) is None
    assert await validate_egress_url_async(None, policy=POLICY) is None


def test_sync_backend_covers_no_timeout_and_terminal_errors() -> None:
    """Cover no-deadline success, last-error propagation, and empty fallback."""
    stream = object()
    backend = _PinnedEgressSyncNetworkBackend(
        "api.example.com", 443, (PUBLIC_ADDRESS,), POLICY
    )
    successful_backend = _SyncBackend([stream])
    backend._backend = successful_backend
    assert backend.connect_tcp("api.example.com", 443, timeout=None) is stream
    assert successful_backend.calls[0][2]["timeout"] is None

    failing_backend = _SyncBackend([OSError("all pinned addresses failed")])
    backend._backend = failing_backend
    with pytest.raises(OSError, match="all pinned addresses failed"):
        backend.connect_tcp("api.example.com", 443)

    backend._addresses = ()
    with pytest.raises(OSError, match="^egress URL is not allowed$"):
        backend.connect_tcp("api.example.com", 443)


def test_build_sync_client_with_valid_url_uses_pinned_transport(monkeypatch) -> None:
    """Cover the successful synchronous client-builder branch without I/O."""
    monkeypatch.setattr(
        validation.socket,
        "getaddrinfo",
        lambda host, port, type=None: [
            (2, 1, 6, "", (PUBLIC_ADDRESS, port))
        ],
    )
    normalized, client = build_egress_sync_client(
        "https://api.example.com/v1", policy=POLICY
    )
    try:
        assert normalized == "https://api.example.com/v1"
        assert client.trust_env is False
    finally:
        client.close()


async def test_async_backend_cancels_and_awaits_pending_tasks() -> None:
    """Cover explicit cleanup of a pending losing connection attempt."""
    backend = _PinnedEgressNetworkBackend(
        "api.example.com", 443, (PUBLIC_ADDRESS,), POLICY
    )
    blocker = asyncio.Event()

    async def wait_forever() -> None:
        await blocker.wait()

    task = asyncio.create_task(wait_forever())
    await asyncio.sleep(0)
    await backend._cancel_and_wait_tasks({task})
    assert task.cancelled()


async def test_async_backend_covers_timeoutless_success_and_sleep(monkeypatch) -> None:
    """Cover the no-deadline connection path and backend sleep delegation."""
    backend = _PinnedEgressNetworkBackend(
        "api.example.com", 443, (PUBLIC_ADDRESS,), POLICY
    )
    stream = _AsyncStream()
    observed_timeouts: list[float | None] = []

    async def connect(address, port, timeout, local_address, socket_options):
        observed_timeouts.append(timeout)
        return stream

    class _SleepingBackend:
        def __init__(self) -> None:
            self.seconds = None

        async def sleep(self, seconds: float) -> None:
            self.seconds = seconds

    sleeping_backend = _SleepingBackend()
    monkeypatch.setattr(backend, "_connect_validated_ip_address", connect)
    backend._backend = sleeping_backend

    assert await backend.connect_tcp("api.example.com", 443, timeout=None) is stream
    await backend.sleep(0.01)
    assert observed_timeouts == [None]
    assert sleeping_backend.seconds == 0.01


async def test_async_backend_closes_simultaneous_extra_stream(monkeypatch) -> None:
    """Close every simultaneously successful stream except the selected winner."""
    backend = _PinnedEgressNetworkBackend(
        "api.example.com",
        443,
        (PUBLIC_ADDRESS, SECOND_PUBLIC_ADDRESS),
        POLICY,
    )
    streams = [_AsyncStream(), _AsyncStream()]
    stream_iter = iter(streams)
    wait_calls = 0

    async def connect(address, port, timeout, local_address, socket_options):
        return next(stream_iter)

    async def deterministic_wait(tasks, **kwargs):
        nonlocal wait_calls
        wait_calls += 1
        if wait_calls == 1:
            return set(), set(tasks)
        await asyncio.gather(*tasks)
        return set(tasks), set()

    monkeypatch.setattr(backend, "_connect_validated_ip_address", connect)
    monkeypatch.setattr(async_transport.asyncio, "wait", deterministic_wait)

    selected = await backend.connect_tcp("api.example.com", 443)
    assert selected in streams
    assert sum(stream.closed for stream in streams) == 1


async def test_async_backend_covers_spurious_empty_wait_with_no_more_addresses(
    monkeypatch,
) -> None:
    """Remain safe if a backend wait reports no completion after exhaustion."""
    backend = _PinnedEgressNetworkBackend(
        "api.example.com", 443, (PUBLIC_ADDRESS,), POLICY
    )
    stream = _AsyncStream()
    real_wait = asyncio.wait
    wait_calls = 0

    async def connect(address, port, timeout, local_address, socket_options):
        return stream

    async def spurious_wait(tasks, **kwargs):
        nonlocal wait_calls
        wait_calls += 1
        if wait_calls <= 2:
            return set(), set(tasks)
        return await real_wait(tasks, **kwargs)

    monkeypatch.setattr(backend, "_connect_validated_ip_address", connect)
    monkeypatch.setattr(async_transport.asyncio, "wait", spurious_wait)

    assert await backend.connect_tcp("api.example.com", 443) is stream


async def test_async_backend_covers_expired_budget_before_wait(monkeypatch) -> None:
    """Stop scheduling new addresses when the timeout budget is already spent."""
    backend = _PinnedEgressNetworkBackend(
        "api.example.com",
        443,
        (PUBLIC_ADDRESS, SECOND_PUBLIC_ADDRESS),
        POLICY,
    )
    stream = _AsyncStream()

    async def connect(address, port, timeout, local_address, socket_options):
        return stream

    monkeypatch.setattr(backend, "_connect_validated_ip_address", connect)
    monkeypatch.setattr(
        async_transport.asyncio,
        "get_running_loop",
        lambda: _FakeClock(0.0, 0.0, 0.0, 0.0, 1.0, 1.0),
    )

    assert await backend.connect_tcp("api.example.com", 443, timeout=0.0) is stream


async def test_async_backend_raises_last_error_after_deadline(monkeypatch) -> None:
    """Stop the race and propagate the final backend error after deadline expiry."""
    backend = _PinnedEgressNetworkBackend(
        "api.example.com",
        443,
        (PUBLIC_ADDRESS, SECOND_PUBLIC_ADDRESS),
        POLICY,
    )

    async def fail(address, port, timeout, local_address, socket_options):
        raise OSError("synthetic connect failure")

    monkeypatch.setattr(backend, "_connect_validated_ip_address", fail)
    monkeypatch.setattr(
        async_transport.asyncio,
        "get_running_loop",
        lambda: _FakeClock(0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 2.0),
    )

    with pytest.raises(OSError, match="synthetic connect failure"):
        await backend.connect_tcp("api.example.com", 443, timeout=1.0)


async def test_async_backend_empty_address_iterator_raises_generic_error() -> None:
    """Cover the defensive terminal path if internal addresses are emptied."""
    backend = _PinnedEgressNetworkBackend(
        "api.example.com", 443, (PUBLIC_ADDRESS,), POLICY
    )
    backend._addresses = ()

    with pytest.raises(OSError, match="^egress URL is not allowed$"):
        await backend.connect_tcp("api.example.com", 443)


async def test_build_async_client_with_valid_url_uses_pinned_transport(monkeypatch) -> None:
    """Cover the successful asynchronous client-builder branch without I/O."""
    monkeypatch.setattr(
        validation.socket,
        "getaddrinfo",
        lambda host, port, type=None: [
            (2, 1, 6, "", (PUBLIC_ADDRESS, port))
        ],
    )
    normalized, client = await build_egress_http_client(
        "https://api.example.com/v1", policy=POLICY
    )
    try:
        assert normalized == "https://api.example.com/v1"
        assert client.trust_env is False
    finally:
        await client.aclose()
