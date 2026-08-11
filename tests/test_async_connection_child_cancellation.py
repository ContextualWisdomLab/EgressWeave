"""Regression for dependency child cancellation in the pinned connection race."""

from __future__ import annotations

import asyncio

import pytest

from egressweave import EgressPolicy
from egressweave.transport import _PinnedEgressNetworkBackend


class _SelfCancellingBackend:
    """Raise child-local cancellation instead of completing one TCP attempt."""

    async def connect_tcp(
        self,
        host,
        port,
        timeout=None,
        local_address=None,
        socket_options=None,
    ):
        """Expose cancellation originating from the dependency child task."""
        raise asyncio.CancelledError("private child cancellation")


@pytest.mark.asyncio
async def test_child_self_cancellation_is_generic_connection_denial() -> None:
    """Contain child cancellation while leaving coordinator cancellation distinct."""
    policy = EgressPolicy.from_hosts("api.example.com")
    backend = _PinnedEgressNetworkBackend(
        "api.example.com",
        443,
        ("93.184.216.34",),
        policy,
    )
    backend._backend = _SelfCancellingBackend()

    with pytest.raises(OSError, match="^egress URL is not allowed$") as caught:
        await backend.connect_tcp("api.example.com", 443, timeout=0.2)

    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None
