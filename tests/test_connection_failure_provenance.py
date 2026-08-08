"""Regression tests for generic connection-failure provenance boundaries."""

from __future__ import annotations

from importlib import import_module

import pytest

from egressweave import EgressPolicy


async_transport_module = import_module("egressweave.transport")
sync_transport_module = import_module("egressweave.sync_transport")

_POLICY = EgressPolicy.from_hosts("api.example.com")
_ADDRESSES = ("93.184.216.34", "1.1.1.1")


class _AsyncSensitiveFailureBackend:
    """Fail every async candidate with address-bearing private detail."""

    def __init__(self) -> None:
        self.started_hosts: list[str] = []

    async def connect_tcp(
        self,
        host,
        port,
        timeout=None,
        local_address=None,
        socket_options=None,
    ):
        self.started_hosts.append(host)
        raise OSError(f"sensitive child failure for {host}")


class _SyncSensitiveFailureBackend:
    """Fail every sync candidate with address-bearing private detail."""

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
        self.started_hosts.append(host)
        raise OSError(f"sensitive child failure for {host}")


@pytest.mark.asyncio
async def test_async_all_candidate_failures_erase_child_error_provenance() -> None:
    """Expose only the generic denial after every async candidate fails."""
    backend = async_transport_module._PinnedEgressNetworkBackend(
        "api.example.com", 443, _ADDRESSES, _POLICY
    )
    failing_backend = _AsyncSensitiveFailureBackend()
    backend._backend = failing_backend

    with pytest.raises(OSError) as error:
        await backend.connect_tcp("api.example.com", 443, timeout=1.0)

    assert str(error.value) == "egress URL is not allowed"
    assert error.value.__context__ is None
    assert error.value.__cause__ is None
    assert failing_backend.started_hosts == list(_ADDRESSES)


def test_sync_all_candidate_failures_erase_child_error_provenance() -> None:
    """Expose only the generic denial after every sync candidate fails."""
    backend = sync_transport_module._PinnedEgressSyncNetworkBackend(
        "api.example.com", 443, _ADDRESSES, _POLICY
    )
    failing_backend = _SyncSensitiveFailureBackend()
    backend._backend = failing_backend

    with pytest.raises(OSError) as error:
        backend.connect_tcp("api.example.com", 443, timeout=1.0)

    assert str(error.value) == "egress URL is not allowed"
    assert error.value.__context__ is None
    assert error.value.__cause__ is None
    assert failing_backend.started_hosts == list(_ADDRESSES)
