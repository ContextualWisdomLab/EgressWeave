"""Regression tests for DNS resolver worker-start failure containment."""

from __future__ import annotations

import pytest

from egressweave import (
    EGRESS_NOT_ALLOWED,
    EgressNotAllowedError,
    EgressPolicy,
    validation,
)

_HOSTNAME = "worker-start.example.com"
_PORT = 443
_AUTHORITY_KEY = (_HOSTNAME, _PORT)
_POLICY = EgressPolicy.from_hosts(_HOSTNAME)


class _CountingResolutionSlots:
    """Record resolver-slot acquisitions and releases for start-failure tests."""

    def __init__(self) -> None:
        self.acquire_count = 0
        self.release_count = 0

    def acquire(self, *, timeout: float) -> bool:
        """Record one successful slot acquisition."""
        assert timeout > 0
        self.acquire_count += 1
        return True

    def release(self) -> None:
        """Record one resolver-slot release."""
        self.release_count += 1


class _SyntheticThreadStartFailure(Exception):
    """Model a non-RuntimeError ordinary failure before the resolver worker starts."""


def _install_failing_resolver_thread(monkeypatch, failure: Exception) -> None:
    """Fail only EgressWeave's resolver thread while preserving other threads."""
    original_thread = validation.threading.Thread

    class _BrokenThread:
        """Synthetic resolver thread that fails before any worker can run."""

        def start(self) -> None:
            """Raise the configured platform startup failure."""
            raise failure

    def selective_thread(*args, **kwargs):
        if kwargs.get("name") == "egressweave-dns-resolver":
            return _BrokenThread()
        return original_thread(*args, **kwargs)

    monkeypatch.setattr(validation.threading, "Thread", selective_thread)


def _assert_generic_start_failure(monkeypatch, failure: Exception) -> None:
    """Require one failed worker start to release its slot and flight."""
    slots = _CountingResolutionSlots()
    monkeypatch.setattr(validation, "_DNS_RESOLUTION_SLOTS", slots)
    _install_failing_resolver_thread(monkeypatch, failure)

    try:
        with pytest.raises(
            EgressNotAllowedError,
            match=f"^{EGRESS_NOT_ALLOWED}$",
        ) as exc_info:
            validation._resolve_all_global_addresses(_HOSTNAME, _PORT, _POLICY)
    finally:
        with validation._DNS_RESOLUTION_FLIGHTS_LOCK:
            validation._DNS_RESOLUTION_FLIGHTS.pop(_AUTHORITY_KEY, None)

    assert exc_info.value.__cause__ is None
    assert exc_info.value.__context__ is None
    assert slots.acquire_count == 1
    assert slots.release_count == slots.acquire_count
    with validation._DNS_RESOLUTION_FLIGHTS_LOCK:
        assert _AUTHORITY_KEY not in validation._DNS_RESOLUTION_FLIGHTS


def test_dns_worker_start_runtime_failure_erases_private_provenance(monkeypatch) -> None:
    """Normalize the documented RuntimeError startup failure and clean resources."""
    _assert_generic_start_failure(
        monkeypatch,
        RuntimeError("private thread-start detail"),
    )


def test_dns_worker_start_non_runtime_failure_fails_closed(monkeypatch) -> None:
    """Clean resources when an ordinary non-RuntimeError failure prevents startup."""
    _assert_generic_start_failure(
        monkeypatch,
        _SyntheticThreadStartFailure("private thread-start detail"),
    )
