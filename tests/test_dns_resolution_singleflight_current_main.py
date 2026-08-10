"""Current-main RED contract for bounded same-authority DNS resolver work."""

from __future__ import annotations

import queue
import threading
import time

from egressweave import (
    EGRESS_NOT_ALLOWED,
    EgressNotAllowedError,
    EgressPolicy,
    validate_egress_url_details,
    validation,
)

AUTHORITY = ("api.example.com", 443)
PUBLIC_ADDRESS = "93.184.216.34"
CALLER_COUNT = 4
DNS_TIMEOUT_SECONDS = 0.10


class _CountingResolutionSlots:
    """Allow resolver work while recording acquired and released worker slots."""

    def __init__(self) -> None:
        self.acquire_count = 0
        self.release_count = 0
        self._condition = threading.Condition()

    def acquire(self, *, timeout: float) -> bool:
        """Record one successful resolver-slot acquisition."""
        assert timeout > 0
        with self._condition:
            self.acquire_count += 1
            self._condition.notify_all()
        return True

    def release(self) -> None:
        """Record one resolver-slot release."""
        with self._condition:
            self.release_count += 1
            self._condition.notify_all()

    def wait_until_balanced(self, timeout: float) -> bool:
        """Wait until every acquired resolver slot has been released."""
        deadline = time.monotonic() + timeout
        with self._condition:
            while self.release_count < self.acquire_count:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return False
                self._condition.wait(remaining)
            return True


def test_same_authority_timeouts_share_one_live_resolver(monkeypatch) -> None:
    """Overlapping callers must not multiply one slow authority's resolver work."""
    slots = _CountingResolutionSlots()
    release_resolver = threading.Event()
    call_lock = threading.Lock()
    caller_barrier = threading.Barrier(CALLER_COUNT + 1)
    outcomes: queue.Queue[str] = queue.Queue()
    call_count = 0

    def slow_getaddrinfo(hostname, port, *, type):
        nonlocal call_count
        assert (hostname, port) == AUTHORITY
        assert type == validation.socket.SOCK_STREAM
        with call_lock:
            call_count += 1
        if not release_resolver.wait(timeout=5.0):
            raise RuntimeError("test resolver was not released")
        return [(2, 1, 6, "", (PUBLIC_ADDRESS, port))]

    monkeypatch.setattr(validation.socket, "getaddrinfo", slow_getaddrinfo)
    monkeypatch.setattr(validation, "_DNS_RESOLUTION_SLOTS", slots)
    policy = EgressPolicy.from_hosts(
        AUTHORITY[0],
        dns_timeout_seconds=DNS_TIMEOUT_SECONDS,
    )

    def validate_from_caller() -> None:
        try:
            caller_barrier.wait(timeout=5.0)
            validate_egress_url_details(
                f"https://{AUTHORITY[0]}",
                policy=policy,
            )
        except EgressNotAllowedError as exc:
            outcomes.put(str(exc))
        except Exception as exc:  # noqa: BLE001 - preserve thread diagnostics
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
        with call_lock:
            assert call_count == 1
        assert slots.acquire_count == 1
    finally:
        release_resolver.set()
        assert slots.wait_until_balanced(timeout=3.0)
