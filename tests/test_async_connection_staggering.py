"""Regression tests for RFC 8305-style staggered connection attempts."""

from __future__ import annotations

import asyncio

import pytest

from egressweave import EgressPolicy
from egressweave import transport as transport_module
from egressweave.transport import _PinnedEgressNetworkBackend


class _FailingBackend:
    """Record attempt starts and keep each candidate active briefly."""

    def __init__(self) -> None:
        self.started_at: list[float] = []

    async def connect_tcp(
        self,
        host,
        port,
        timeout=None,
        local_address=None,
        socket_options=None,
    ):
        self.started_at.append(asyncio.get_running_loop().time())
        await asyncio.sleep(0.03)
        raise OSError(f"connection failed for {host}")


class _ImmediateSuccessBackend:
    """Return the first stream immediately so later candidates stay unstarted."""

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
        self.started_hosts.append(host)
        return self.stream


class _TimeoutIgnoringBackend:
    """Stay pending until cancelled, deliberately ignoring child timeout metadata."""

    def __init__(self) -> None:
        self.started_hosts: list[str] = []
        self.cancelled_hosts: list[str] = []

    async def connect_tcp(
        self,
        host,
        port,
        timeout=None,
        local_address=None,
        socket_options=None,
    ):
        self.started_hosts.append(host)
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            self.cancelled_hosts.append(host)
            raise


def _backend_with_three_addresses() -> _PinnedEgressNetworkBackend:
    policy = EgressPolicy.from_hosts("api.example.com")
    return _PinnedEgressNetworkBackend(
        "api.example.com",
        443,
        ("93.184.216.34", "1.1.1.1", "8.8.8.8"),
        policy,
    )


@pytest.mark.asyncio
async def test_connection_attempts_are_staggered(monkeypatch) -> None:
    monkeypatch.setattr(
        transport_module,
        "_CONNECTION_ATTEMPT_DELAY_SECONDS",
        0.01,
    )
    backend = _backend_with_three_addresses()
    recording_backend = _FailingBackend()
    backend._backend = recording_backend

    with pytest.raises(OSError):
        await backend.connect_tcp("api.example.com", 443, timeout=0.2)

    assert len(recording_backend.started_at) == 3
    first_gap = recording_backend.started_at[1] - recording_backend.started_at[0]
    second_gap = recording_backend.started_at[2] - recording_backend.started_at[1]
    assert first_gap >= 0.007
    assert second_gap >= 0.007


@pytest.mark.asyncio
async def test_first_success_prevents_unnecessary_connection_attempts(monkeypatch) -> None:
    monkeypatch.setattr(
        transport_module,
        "_CONNECTION_ATTEMPT_DELAY_SECONDS",
        0.01,
    )
    backend = _backend_with_three_addresses()
    successful_backend = _ImmediateSuccessBackend()
    backend._backend = successful_backend

    stream = await backend.connect_tcp("api.example.com", 443, timeout=0.2)

    assert stream is successful_backend.stream
    assert successful_backend.started_hosts == ["93.184.216.34"]


@pytest.mark.asyncio
async def test_connection_race_enforces_its_global_deadline(monkeypatch) -> None:
    """Require the coordinator to stop even when child connects ignore timeouts."""
    monkeypatch.setattr(
        transport_module,
        "_CONNECTION_ATTEMPT_DELAY_SECONDS",
        0.01,
    )
    backend = _backend_with_three_addresses()
    ignoring_backend = _TimeoutIgnoringBackend()
    backend._backend = ignoring_backend

    with pytest.raises(OSError) as error:
        await asyncio.wait_for(
            backend.connect_tcp("api.example.com", 443, timeout=0.04),
            timeout=0.2,
        )

    assert str(error.value) == "egress URL is not allowed"
    assert ignoring_backend.started_hosts
    assert ignoring_backend.cancelled_hosts == ignoring_backend.started_hosts
