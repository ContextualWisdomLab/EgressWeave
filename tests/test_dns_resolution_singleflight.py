"""Regression contracts for bounded in-flight DNS resolution work."""

from __future__ import annotations

import asyncio
import queue
import threading
import time

import pytest

from egressweave import (
    EGRESS_NOT_ALLOWED,
    EgressNotAllowedError,
    EgressPolicy,
    validate_egress_url_details,
    validate_egress_url_details_async,
)
from egressweave import validation

PUBLIC_ADDRESS = "93.184.216.34"
CALLER_COUNT = 4
DNS_TIMEOUT_SECONDS = 0.75


class _CountingResolutionSlots:
    """Allow resolver work while recording acquired and released worker slots."""

    def __init__(self) -> None:
        self.acquire_count = 0
        self.release_count = 0
        self._condition = threading.Condition()

    def acquire(self, *, timeout: float) -> bool:
        """Record one successful acquisition without imposing a test-only ceiling."""
        assert timeout > 0
        with self._condition:
            self.acquire_count += 1
            self._condition.notify_all()
        return True

    def release(self) -> None:
        """Record one worker-slot release."""
        with self._condition:
            self.release_count += 1
            self._condition.notify_all()

    def wait_until_balanced(self, timeout: float) -> bool:
        """Wait until every slot acquired by this test has been released."""
        deadline = time.monotonic() + timeout
        with self._condition:
            while self.release_count < self.acquire_count:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return False
                self._condition.wait(remaining)
            return True


def _install_blocking_resolver(monkeypatch):
    """Install one deterministic resolver that stays live past caller deadlines."""
    release_resolver = threading.Event()
    call_lock = threading.Lock()
    call_count = 0

    def slow_getaddrinfo(hostname, port, *, type):
        nonlocal call_count
        assert hostname == "api.example.com"
        assert port == 443
        assert type == validation.socket.SOCK_STREAM
        with call_lock:
            call_count += 1
        if not release_resolver.wait(timeout=5.0):
            raise RuntimeError("test resolver was not released")
        return [(2, 1, 6, "", (PUBLIC_ADDRESS, port))]

    monkeypatch.setattr(validation.socket, "getaddrinfo", slow_getaddrinfo)

    def observed_calls() -> int:
        with call_lock:
            return call_count

    return release_resolver, observed_calls


def _policy() -> EgressPolicy:
    """Return the short-deadline policy used by the concurrency regressions."""
    return EgressPolicy.from_hosts(
        "api.example.com",
        dns_timeout_seconds=DNS_TIMEOUT_SECONDS,
    )


def test_sync_same_authority_timeouts_share_one_live_resolver(monkeypatch) -> None:
    """Repeated sync timeouts for one authority must share one live DNS worker."""
    slots = _CountingResolutionSlots()
    release_resolver, observed_calls = _install_blocking_resolver(monkeypatch)
    monkeypatch.setattr(validation, "_DNS_RESOLUTION_SLOTS", slots)
    caller_barrier = threading.Barrier(CALLER_COUNT + 1)
    outcomes: queue.Queue[str] = queue.Queue()

    def validate_from_caller() -> None:
        try:
            caller_barrier.wait(timeout=5.0)
            validate_egress_url_details(
                "https://api.example.com",
                policy=_policy(),
            )
        except EgressNotAllowedError as exc:
            outcomes.put(str(exc))
        except BaseException as exc:  # pragma: no cover - diagnostic only
            outcomes.put(f"unexpected {type(exc).__name__}: {exc}")
        else:
            outcomes.put("unexpected success")

    callers = [
        threading.Thread(target=validate_from_caller, name=f"dns-caller-{index}")
        for index in range(CALLER_COUNT)
    ]
    for caller in callers:
        caller.start()

    try:
        caller_barrier.wait(timeout=5.0)
        for caller in callers:
            caller.join(timeout=DNS_TIMEOUT_SECONDS + 2.0)

        assert not any(caller.is_alive() for caller in callers)
        assert sorted(outcomes.get_nowait() for _ in range(CALLER_COUNT)) == [
            EGRESS_NOT_ALLOWED
        ] * CALLER_COUNT
        assert observed_calls() == 1
        assert slots.acquire_count == 1
    finally:
        release_resolver.set()
        assert slots.wait_until_balanced(timeout=3.0)


async def test_async_same_authority_timeouts_share_one_live_resolver(monkeypatch) -> None:
    """Repeated async timeouts for one authority must share the same live worker."""
    slots = _CountingResolutionSlots()
    release_resolver, observed_calls = _install_blocking_resolver(monkeypatch)
    monkeypatch.setattr(validation, "_DNS_RESOLUTION_SLOTS", slots)
    start_callers = asyncio.Event()

    async def validate_from_caller() -> None:
        await start_callers.wait()
        with pytest.raises(
            EgressNotAllowedError,
            match=f"^{EGRESS_NOT_ALLOWED}$",
        ):
            await validate_egress_url_details_async(
                "https://api.example.com",
                policy=_policy(),
            )

    callers = [asyncio.create_task(validate_from_caller()) for _ in range(CALLER_COUNT)]
    await asyncio.sleep(0)

    try:
        start_callers.set()
        await asyncio.wait_for(
            asyncio.gather(*callers),
            timeout=DNS_TIMEOUT_SECONDS + 3.0,
        )
        assert observed_calls() == 1
        assert slots.acquire_count == 1
    finally:
        release_resolver.set()
        assert slots.wait_until_balanced(timeout=3.0)
