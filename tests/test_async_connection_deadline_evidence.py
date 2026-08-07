"""Focused evidence for deadline-boundary connection cleanup and masking."""

from __future__ import annotations

import asyncio

import pytest

from egressweave import EgressPolicy
from egressweave import transport as transport_module
from egressweave.transport import _PinnedEgressNetworkBackend


class _TrackingSynchronousCloseFailureStream:
    """Record cleanup before raising synchronously from ``aclose``."""

    def __init__(self) -> None:
        self.close_called = False

    def aclose(self):
        """Record invocation and expose a hostile synchronous cleanup failure."""
        self.close_called = True
        raise RuntimeError("sensitive synchronous close failure")


class _TrackingAwaitedCloseFailureStream:
    """Record cleanup before raising while ``aclose`` is awaited."""

    def __init__(self) -> None:
        self.close_called = False

    async def aclose(self) -> None:
        """Record invocation and expose a hostile awaited cleanup failure."""
        self.close_called = True
        raise RuntimeError("sensitive awaited close failure")


class _TrackingCancelledCloseFailureStream:
    """Record cleanup before a dependency-injected child self-cancels."""

    def __init__(self) -> None:
        self.close_called = False

    async def aclose(self) -> None:
        """Record invocation and raise child cancellation from cleanup."""
        self.close_called = True
        raise asyncio.CancelledError


class _BlockingCloseStream:
    """Block inside ``aclose`` so coordinator cancellation can be observed."""

    def __init__(self, close_started: asyncio.Event) -> None:
        self.close_started = close_started
        self.close_called = False

    async def aclose(self) -> None:
        """Record cleanup and wait until the parent coordinator is cancelled."""
        self.close_called = True
        self.close_started.set()
        await asyncio.Event().wait()


class _TrackingSuccessBackend:
    """Return one configured stream and record candidate starts."""

    def __init__(self, stream) -> None:
        self.stream = stream
        self.started_hosts: list[str] = []

    async def connect_tcp(
        self,
        host,
        port,
        timeout=None,
        local_address=None,
        socket_options=None,
    ):
        """Record the attempted host and return the configured stream."""
        self.started_hosts.append(host)
        return self.stream


class _TrackingMultipleSuccessBackend:
    """Return one hostile-close stream per candidate while recording starts."""

    def __init__(self, stream_type) -> None:
        self._stream_type = stream_type
        self.started_hosts: list[str] = []
        self.streams: list[
            _TrackingAwaitedCloseFailureStream
            | _TrackingCancelledCloseFailureStream
        ] = []

    async def connect_tcp(
        self,
        host,
        port,
        timeout=None,
        local_address=None,
        socket_options=None,
    ):
        """Create and return a distinct successful stream for this candidate."""
        self.started_hosts.append(host)
        stream = self._stream_type()
        self.streams.append(stream)
        return stream


class _TrackingBlockingSuccessBackend:
    """Return blocking-close streams so parent cancellation remains observable."""

    def __init__(self, close_started: asyncio.Event) -> None:
        self.close_started = close_started
        self.started_hosts: list[str] = []
        self.streams: list[_BlockingCloseStream] = []

    async def connect_tcp(
        self,
        host,
        port,
        timeout=None,
        local_address=None,
        socket_options=None,
    ):
        """Create a distinct successful stream whose cleanup blocks."""
        self.started_hosts.append(host)
        stream = _BlockingCloseStream(self.close_started)
        self.streams.append(stream)
        return stream


class _TrackingFailureBackend:
    """Raise a sensitive child error while recording candidate starts."""

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
        """Record the attempted host before raising a child-specific error."""
        self.started_hosts.append(host)
        raise OSError(f"sensitive child failure for {host}")


class _FakeLoopClock:
    """Provide deterministic monotonic time for a deadline-boundary wait."""

    def __init__(self) -> None:
        self.now = 0.0

    def time(self) -> float:
        """Return the test-controlled monotonic timestamp."""
        return self.now


def _backend_with_three_addresses() -> _PinnedEgressNetworkBackend:
    """Build the pinned backend used by focused deadline regressions."""
    policy = EgressPolicy.from_hosts("api.example.com")
    return _PinnedEgressNetworkBackend(
        "api.example.com",
        443,
        ("93.184.216.34", "1.1.1.1", "8.8.8.8"),
        policy,
    )


def _install_deadline_boundary_wait(monkeypatch) -> None:
    """Make the first completed child become observable exactly at the deadline."""
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


def _install_two_successes_before_deadline(monkeypatch) -> None:
    """Expose two successful attempts together while the shared budget remains."""
    clock = _FakeLoopClock()
    wait_calls = 0

    async def wait_before_deadline(tasks, *, timeout, return_when):
        nonlocal wait_calls
        assert timeout is not None
        assert return_when is asyncio.FIRST_COMPLETED
        wait_calls += 1
        await asyncio.sleep(0)
        if wait_calls == 1:
            clock.now = 0.25
            assert len(tasks) == 1
            return set(), set(tasks)
        assert wait_calls == 2
        assert len(tasks) == 2
        await asyncio.gather(*tasks)
        clock.now = 0.5
        return set(tasks), set()

    monkeypatch.setattr(transport_module.asyncio, "get_running_loop", lambda: clock)
    monkeypatch.setattr(transport_module.asyncio, "wait", wait_before_deadline)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "stream_type",
    [_TrackingSynchronousCloseFailureStream, _TrackingAwaitedCloseFailureStream],
)
async def test_deadline_cleanup_invokes_hostile_stream_close(monkeypatch, stream_type) -> None:
    """Prove deadline denial actually invokes cleanup before masking its failure."""
    _install_deadline_boundary_wait(monkeypatch)
    backend = _backend_with_three_addresses()
    stream = stream_type()
    tracking_backend = _TrackingSuccessBackend(stream)
    backend._backend = tracking_backend

    with pytest.raises(OSError) as error:
        await backend.connect_tcp("api.example.com", 443, timeout=1.0)

    assert str(error.value) == "egress URL is not allowed"
    assert error.value.__context__ is None
    assert error.value.__cause__ is None
    assert stream.close_called is True
    assert tracking_backend.started_hosts == ["93.184.216.34"]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "stream_type",
    [_TrackingAwaitedCloseFailureStream, _TrackingCancelledCloseFailureStream],
)
async def test_predeadline_losing_stream_cleanup_cannot_replace_selected_stream(
    monkeypatch,
    stream_type,
) -> None:
    """Return one winner even when simultaneous loser cleanup fails."""
    _install_two_successes_before_deadline(monkeypatch)
    backend = _backend_with_three_addresses()
    tracking_backend = _TrackingMultipleSuccessBackend(stream_type)
    backend._backend = tracking_backend

    selected_stream = await backend.connect_tcp(
        "api.example.com",
        443,
        timeout=1.0,
    )

    assert selected_stream in tracking_backend.streams
    assert tracking_backend.started_hosts == ["93.184.216.34", "1.1.1.1"]
    assert sum(stream.close_called for stream in tracking_backend.streams) == 1
    assert selected_stream.close_called is False


@pytest.mark.asyncio
async def test_predeadline_loser_cleanup_preserves_coordinator_cancellation(
    monkeypatch,
) -> None:
    """Propagate cancellation directed at the coordinator during loser cleanup."""
    _install_two_successes_before_deadline(monkeypatch)
    close_started = asyncio.Event()
    backend = _backend_with_three_addresses()
    tracking_backend = _TrackingBlockingSuccessBackend(close_started)
    backend._backend = tracking_backend
    connection_task = asyncio.create_task(
        backend.connect_tcp("api.example.com", 443, timeout=1.0)
    )

    await asyncio.wait_for(close_started.wait(), timeout=1.0)
    connection_task.cancel()

    with pytest.raises(asyncio.CancelledError):
        await connection_task

    assert tracking_backend.started_hosts == ["93.184.216.34", "1.1.1.1"]
    assert sum(stream.close_called for stream in tracking_backend.streams) == 1


@pytest.mark.asyncio
async def test_deadline_masks_child_error_without_starting_second_candidate(monkeypatch) -> None:
    """Prove child errors and post-deadline candidate starts stay hidden and absent."""
    _install_deadline_boundary_wait(monkeypatch)
    backend = _backend_with_three_addresses()
    tracking_backend = _TrackingFailureBackend()
    backend._backend = tracking_backend

    with pytest.raises(OSError) as error:
        await backend.connect_tcp("api.example.com", 443, timeout=1.0)

    assert str(error.value) == "egress URL is not allowed"
    assert error.value.__context__ is None
    assert error.value.__cause__ is None
    assert tracking_backend.started_hosts == ["93.184.216.34"]
