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


def test_dns_worker_start_failure_erases_private_exception_provenance(monkeypatch) -> None:
    """Reject thread-start failure without retaining dependency-controlled details."""

    class _BrokenThread:
        """Synthetic resolver thread that fails before any worker can run."""

        def start(self) -> None:
            """Raise one dependency-controlled platform startup failure."""
            raise RuntimeError("private thread-start detail")

    monkeypatch.setattr(
        validation.threading,
        "Thread",
        lambda **kwargs: _BrokenThread(),
    )

    with pytest.raises(
        EgressNotAllowedError,
        match=f"^{EGRESS_NOT_ALLOWED}$",
    ) as exc_info:
        validation._resolve_all_global_addresses(_HOSTNAME, _PORT, _POLICY)

    assert exc_info.value.__cause__ is None
    assert exc_info.value.__context__ is None
    with validation._DNS_RESOLUTION_FLIGHTS_LOCK:
        assert _AUTHORITY_KEY not in validation._DNS_RESOLUTION_FLIGHTS
