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


class _ClosingStream:
    """Record whether a completed connection stream was closed."""

    def __init__(self) -> None:
        self.closed = False

    async def aclose(self) -> None:
        """Record deadline cleanup of a completed connection stream."""
        self.closed = True


class _SynchronousCloseFailureStream:
    """Raise before returning an awaitable when deadline cleanup requests close."""

    def aclose(self):
        """Expose a hostile synchronous cleanup failure from an injected stream."""
        raise RuntimeError("sensitive synchronous close failure")


class _AwaitedCloseFailureStream:
    """Raise while awaiting deadline cleanup from an injected stream."""

    async def aclose(self) -> None:
        """Expose a hostile asynchronous cleanup failure from an injected stream."""
        raise RuntimeError("sensitive awaited close failure")


class _DeadlineBoundarySuccessBackend:
    """Return one closeable stream immediately at the coordinator boundary."""

    def __init__(self) -> None:
        self.stream = _ClosingStream()

    async def connect_tcp(
        self,
        host,
        port,
        timeout=None,
        local_address=None,
        socket_options=None,
    ):
        return self.stream


class _DeadlineBoundarySynchronousCloseFailureBackend:
    """Return a stream whose cleanup raises before producing an awaitable."""

    def __init__(self) -> None:
        self.stream = _SynchronousCloseFailureStream()

    async def connect_tcp(
        self,
        host,
        port,
        timeout=None,
        local_address=None,
        socket_options=None,
    ):
        return self.stream


class _DeadlineBoundaryAwaitedCloseFailureBackend:
    """Return a stream whose cleanup raises while its awaitable executes."""

    def __init__(self) -> None:
        self.stream = _AwaitedCloseFailureStream()

    async def connect_tcp(
        self,
        host,
        port,
        timeout=None,
        local_address=None,
        socket_options=None,
    ):
        return self.stream


class _DeadlineBoundaryFailureBackend:
    """Raise a sensitive child error immediately at the coordinator boundary."""

    async def connect_tcp(
        self,
        host,
        port,
        timeout=None,
        local_address=None,
        socket_options=None,
    ):
        raise OSError(f"sensitive child failure for {host}")


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


class _FailThenIgnoreTimeoutBackend:
    """Fail one candidate verbosely, then keep later candidates pending."""

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
        if len(self.started_hosts) == 1:
            raise OSError(f"sensitive child failure for {host}")
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            self.cancelled_hosts.append(host)
            raise


class _FakeLoopClock:
    """Provide deterministic monotonic time for deadline-boundary regressions."""

    def __init__(self) -> None:
        self.now = 0.0

    def time(self) -> float:
        """Return the test-controlled monotonic timestamp."""
        return self.now


class _SequenceLoopClock:
    """Return deterministic timestamps and then hold the final timestamp."""

    def __init__(self, *timestamps: float) -> None:
        self._timestamps = list(timestamps)
        self._last = timestamps[-1]

    def time(self) -> float:
        """Return the next configured monotonic timestamp."""
        if self._timestamps:
            self._last = self._timestamps.pop(0)
        return self._last


def _install_deadline_boundary_wait(monkeypatch) -> None:
    """Make the first completed task become visible exactly at the deadline."""
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


def _backend_with_three_addresses() -> _PinnedEgressNetworkBackend:
    policy = EgressPolicy.from_hosts("api.example.com")
    return _PinnedEgressNetworkBackend(
        "api.example.com",
        443,
        ("93.184.216.34", "1.1.1.1", "8.8.8.8"),
        policy,
    )


@pytest.mark.asyncio
async def test_zero_budget_does_not_create_initial_connection_task(monkeypatch) -> None:
    """Do not create even the first child after an already exhausted deadline."""
    backend = _backend_with_three_addresses()
    ignoring_backend = _TimeoutIgnoringBackend()
    backend._backend = ignoring_backend
    real_create_task = asyncio.create_task
    created_task_count = 0

    def tracked_create_task(coro):
        nonlocal created_task_count
        created_task_count += 1
        return real_create_task(coro)

    monkeypatch.setattr(transport_module.asyncio, "create_task", tracked_create_task)

    with pytest.raises(OSError, match="^egress URL is not allowed$"):
        await backend.connect_tcp("api.example.com", 443, timeout=0.0)

    assert created_task_count == 0
    assert ignoring_backend.started_hosts == []


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
        # Leave scheduling headroom so this behavioral assertion stays stable
        # when the shared CI runner is busy.
        await backend.connect_tcp("api.example.com", 443, timeout=1.0)

    assert len(recording_backend.started_at) == 3
    first_gap = recording_backend.started_at[1] - recording_backend.started_at[0]
    second_gap = recording_backend.started_at[2] - recording_backend.started_at[1]
    assert first_gap >= 0.007
    assert second_gap >= 0.007


@pytest.mark.asyncio
async def test_connection_stagger_waits_when_scheduler_runs_early(monkeypatch) -> None:
    """Keep the real-start backoff when a scheduler wake-up is premature."""
    monkeypatch.setattr(
        transport_module,
        "_CONNECTION_ATTEMPT_DELAY_SECONDS",
        0.01,
    )
    backend = _backend_with_three_addresses()
    stream = object()
    first_started = asyncio.Event()
    attempted: list[str] = []

    async def connect(address, port, timeout, local_address, socket_options):
        attempted.append(address)
        if address == "93.184.216.34":
            first_started.set()
            await asyncio.sleep(0.02)
            raise OSError("first pinned address failed")
        return stream

    monkeypatch.setattr(backend, "_connect_validated_ip_address", connect)
    real_wait = asyncio.wait
    wait_calls = 0

    async def early_wait(tasks, **kwargs):
        nonlocal wait_calls
        wait_calls += 1
        if wait_calls == 1:
            await first_started.wait()
            return set(), set(tasks)
        return await real_wait(tasks, **kwargs)

    monkeypatch.setattr(transport_module.asyncio, "wait", early_wait)

    assert await backend.connect_tcp("api.example.com", 443, timeout=0.2) is stream
    assert attempted == ["93.184.216.34", "1.1.1.1"]


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
async def test_deadline_boundary_rejects_completed_success_and_closes_stream(
    monkeypatch,
) -> None:
    """Reject a completed stream first observed at the shared deadline."""
    _install_deadline_boundary_wait(monkeypatch)
    backend = _backend_with_three_addresses()
    boundary_backend = _DeadlineBoundarySuccessBackend()
    backend._backend = boundary_backend

    with pytest.raises(OSError) as error:
        await backend.connect_tcp("api.example.com", 443, timeout=1.0)

    assert str(error.value) == "egress URL is not allowed"
    assert boundary_backend.stream.closed is True


@pytest.mark.asyncio
async def test_deadline_boundary_masks_synchronous_stream_cleanup_error(
    monkeypatch,
) -> None:
    """Keep a hostile synchronous cleanup failure behind the generic denial."""
    _install_deadline_boundary_wait(monkeypatch)
    backend = _backend_with_three_addresses()
    boundary_backend = _DeadlineBoundarySynchronousCloseFailureBackend()
    backend._backend = boundary_backend

    with pytest.raises(OSError) as error:
        await backend.connect_tcp("api.example.com", 443, timeout=1.0)

    assert str(error.value) == "egress URL is not allowed"
    assert error.value.__context__ is None
    assert error.value.__cause__ is None


@pytest.mark.asyncio
async def test_deadline_boundary_masks_awaited_stream_cleanup_error(
    monkeypatch,
) -> None:
    """Keep an awaited cleanup failure behind the same generic denial."""
    _install_deadline_boundary_wait(monkeypatch)
    backend = _backend_with_three_addresses()
    boundary_backend = _DeadlineBoundaryAwaitedCloseFailureBackend()
    backend._backend = boundary_backend

    with pytest.raises(OSError) as error:
        await backend.connect_tcp("api.example.com", 443, timeout=1.0)

    assert str(error.value) == "egress URL is not allowed"
    assert error.value.__context__ is None
    assert error.value.__cause__ is None


@pytest.mark.asyncio
async def test_deadline_boundary_masks_completed_child_error(monkeypatch) -> None:
    """Never expose a child error first observed at the shared deadline."""
    _install_deadline_boundary_wait(monkeypatch)
    backend = _backend_with_three_addresses()
    backend._backend = _DeadlineBoundaryFailureBackend()

    with pytest.raises(OSError) as error:
        await backend.connect_tcp("api.example.com", 443, timeout=1.0)

    assert str(error.value) == "egress URL is not allowed"


@pytest.mark.asyncio
async def test_predeadline_failure_does_not_start_candidate_after_deadline(
    monkeypatch,
) -> None:
    """Fail generically if the budget expires before the next candidate starts."""
    clock = _SequenceLoopClock(
        0.0,
        0.0,
        0.0,
        0.0,
        0.0,
        0.0,
        0.0,
        0.0,
        0.9,
        1.0,
        1.0,
    )

    async def wait_for_failure(tasks, *, timeout, return_when):
        assert timeout == pytest.approx(0.25)
        assert return_when is asyncio.FIRST_COMPLETED
        await asyncio.sleep(0)
        done = {task for task in tasks if task.done()}
        assert len(done) == 1
        return done, set(tasks) - done

    monkeypatch.setattr(transport_module.asyncio, "get_running_loop", lambda: clock)
    monkeypatch.setattr(transport_module.asyncio, "wait", wait_for_failure)
    backend = _backend_with_three_addresses()
    backend._backend = _DeadlineBoundaryFailureBackend()

    with pytest.raises(OSError, match="^egress URL is not allowed$"):
        await backend.connect_tcp("api.example.com", 443, timeout=1.0)


@pytest.mark.asyncio
async def test_empty_wait_does_not_start_candidate_after_deadline(monkeypatch) -> None:
    """Do not create a later task if an empty wait reaches the shared deadline."""
    clock = _SequenceLoopClock(
        0.0,
        0.0,
        0.0,
        0.0,
        0.0,
        0.0,
        0.0,
        0.0,
        0.9,
        1.0,
        1.0,
    )
    real_create_task = asyncio.create_task
    created_task_count = 0

    def tracked_create_task(coro):
        nonlocal created_task_count
        created_task_count += 1
        return real_create_task(coro)

    async def empty_wait(tasks, *, timeout, return_when):
        assert timeout == pytest.approx(0.25)
        assert return_when is asyncio.FIRST_COMPLETED
        await asyncio.sleep(0)
        return set(), set(tasks)

    monkeypatch.setattr(transport_module.asyncio, "get_running_loop", lambda: clock)
    monkeypatch.setattr(transport_module.asyncio, "wait", empty_wait)
    monkeypatch.setattr(transport_module.asyncio, "create_task", tracked_create_task)
    backend = _backend_with_three_addresses()
    ignoring_backend = _TimeoutIgnoringBackend()
    backend._backend = ignoring_backend

    with pytest.raises(OSError, match="^egress URL is not allowed$"):
        await backend.connect_tcp("api.example.com", 443, timeout=1.0)

    assert created_task_count == 1
    assert ignoring_backend.started_hosts == ["93.184.216.34"]
    assert ignoring_backend.cancelled_hosts == ignoring_backend.started_hosts


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
    assert sorted(ignoring_backend.cancelled_hosts) == sorted(
        ignoring_backend.started_hosts
    )


@pytest.mark.asyncio
async def test_deadline_exhaustion_does_not_leak_an_earlier_child_error(
    monkeypatch,
) -> None:
    """Require deadline exhaustion to preserve the generic policy error boundary."""
    monkeypatch.setattr(
        transport_module,
        "_CONNECTION_ATTEMPT_DELAY_SECONDS",
        0.01,
    )
    backend = _backend_with_three_addresses()
    mixed_backend = _FailThenIgnoreTimeoutBackend()
    backend._backend = mixed_backend

    with pytest.raises(OSError) as error:
        await asyncio.wait_for(
            backend.connect_tcp("api.example.com", 443, timeout=0.04),
            timeout=0.2,
        )

    assert str(error.value) == "egress URL is not allowed"
    assert len(mixed_backend.started_hosts) >= 2
    assert sorted(mixed_backend.cancelled_hosts) == sorted(
        mixed_backend.started_hosts[1:]
    )
