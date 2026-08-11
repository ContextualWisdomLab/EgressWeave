"""Current-main RED evidence for finite pinned connection deadlines."""

from __future__ import annotations

import asyncio

import pytest

from egressweave import EgressPolicy
from egressweave import transport as async_transport_module
from egressweave.sync_transport import _PinnedEgressSyncNetworkBackend
from egressweave.transport import _PinnedEgressNetworkBackend

_HOSTNAME = "api.example.com"
_PORT = 443
_ADDRESSES = ("93.184.216.34", "1.1.1.1")
_POLICY = EgressPolicy.from_hosts(_HOSTNAME)


class _SyncRecordingFailureBackend:
    """Record sync attempts before exposing dependency-specific failure text."""

    def __init__(self) -> None:
        self.started_hosts: list[str] = []

    def connect_tcp(
        self,
        host,
        port,
        timeout=None,
        local_address=None,
        socket_options=None,
    ):
        """Record one delegated TCP attempt and fail with private detail."""
        self.started_hosts.append(host)
        raise OSError(f"sensitive child failure for {host}")


class _AsyncImmediateSuccessBackend:
    """Record async attempts and return an inert stream immediately."""

    def __init__(self) -> None:
        self.started_hosts: list[str] = []
        self.stream = object()

    async def connect_tcp(
        self,
        host,
        port,
        timeout=None,
        local_address=None,
        socket_options=None,
    ):
        """Record one delegated TCP attempt and return immediately."""
        self.started_hosts.append(host)
        return self.stream


def test_sync_zero_budget_starts_no_connection_candidate() -> None:
    """Reject an exhausted synchronous budget before backend delegation."""
    backend = _PinnedEgressSyncNetworkBackend(
        _HOSTNAME,
        _PORT,
        _ADDRESSES,
        _POLICY,
    )
    injected_backend = _SyncRecordingFailureBackend()
    backend._backend = injected_backend

    with pytest.raises(OSError) as error:
        backend.connect_tcp(_HOSTNAME, _PORT, timeout=0.0)

    assert str(error.value) == "egress URL is not allowed"
    assert error.value.__context__ is None
    assert error.value.__cause__ is None
    assert injected_backend.started_hosts == []


@pytest.mark.asyncio
async def test_async_zero_budget_creates_no_connection_task(monkeypatch) -> None:
    """Reject an exhausted async budget before creating the initial child task."""
    backend = _PinnedEgressNetworkBackend(
        _HOSTNAME,
        _PORT,
        _ADDRESSES,
        _POLICY,
    )
    injected_backend = _AsyncImmediateSuccessBackend()
    backend._backend = injected_backend
    real_create_task = asyncio.create_task
    created_tasks = 0

    def tracked_create_task(coro):
        nonlocal created_tasks
        created_tasks += 1
        return real_create_task(coro)

    monkeypatch.setattr(async_transport_module.asyncio, "create_task", tracked_create_task)

    with pytest.raises(OSError) as error:
        await backend.connect_tcp(_HOSTNAME, _PORT, timeout=0.0)

    assert str(error.value) == "egress URL is not allowed"
    assert error.value.__context__ is None
    assert error.value.__cause__ is None
    assert created_tasks == 0
    assert injected_backend.started_hosts == []
