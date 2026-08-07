"""Regression for cancellation raised by deadline stream cleanup."""

from __future__ import annotations

import asyncio

import pytest

from egressweave import EgressPolicy
from egressweave import transport as transport_module
from egressweave.transport import _PinnedEgressNetworkBackend


class _CancelledCleanupStream:
    """Raise ``CancelledError`` while deadline cleanup awaits stream closure."""

    async def aclose(self) -> None:
        """Model a dependency-injected stream that self-cancels during cleanup."""
        raise asyncio.CancelledError("sensitive injected cleanup cancellation")


class _DeadlineBoundaryCancelledCleanupBackend:
    """Return a stream whose deadline cleanup raises ``CancelledError``."""

    def __init__(self) -> None:
        self.stream = _CancelledCleanupStream()

    async def connect_tcp(
        self,
        host,
        port,
        timeout=None,
        local_address=None,
        socket_options=None,
    ):
        """Return the hostile stream immediately at the coordinator boundary."""
        return self.stream


class _FakeLoopClock:
    """Provide deterministic monotonic time for the deadline boundary."""

    def __init__(self) -> None:
        self.now = 0.0

    def time(self) -> float:
        """Return the test-controlled monotonic timestamp."""
        return self.now


def _backend_with_three_addresses() -> _PinnedEgressNetworkBackend:
    """Build the pinned backend used by the focused deadline regression."""
    policy = EgressPolicy.from_hosts("api.example.com")
    return _PinnedEgressNetworkBackend(
        "api.example.com",
        443,
        ("93.184.216.34", "1.1.1.1", "8.8.8.8"),
        policy,
    )


@pytest.mark.asyncio
async def test_deadline_cleanup_masks_child_cancelled_error(monkeypatch) -> None:
    """Keep child self-cancellation behind the stable generic deadline denial."""
    clock = _FakeLoopClock()

    async def wait_at_deadline(tasks, *, timeout, return_when):
        assert timeout is not None
        assert return_when is asyncio.FIRST_COMPLETED
        await asyncio.sleep(0)
        clock.now = 1.0
        done = {task for task in tasks if task.done()}
        assert done
        return done, set(tasks) - done

    monkeypatch.setattr(transport_module.asyncio, "get_running_loop", lambda: clock)
    monkeypatch.setattr(transport_module.asyncio, "wait", wait_at_deadline)
    backend = _backend_with_three_addresses()
    backend._backend = _DeadlineBoundaryCancelledCleanupBackend()

    with pytest.raises(OSError) as error:
        await backend.connect_tcp("api.example.com", 443, timeout=1.0)

    assert str(error.value) == "egress URL is not allowed"
    assert error.value.__context__ is None
    assert error.value.__cause__ is None
