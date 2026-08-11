"""Regression tests for child connection-cleanup control-flow boundaries."""

from __future__ import annotations

import pytest

from egressweave import transport as transport_module


class _ChildCleanupBaseException(BaseException):
    """Represent a dependency-controlled non-Exception cleanup failure."""


class _DirectCleanupFailureStream:
    """Raise one configured failure before returning a cleanup awaitable."""

    def __init__(self, failure: BaseException) -> None:
        self._failure = failure

    def aclose(self):
        """Raise the configured direct cleanup failure."""
        raise self._failure


@pytest.mark.asyncio
async def test_child_cleanup_contains_direct_custom_base_exception() -> None:
    """Do not let a dependency child replace an already-selected outcome."""
    stream = _DirectCleanupFailureStream(
        _ChildCleanupBaseException("sensitive child cleanup failure")
    )

    await transport_module._close_connection_stream_best_effort(stream)


@pytest.mark.asyncio
@pytest.mark.parametrize("failure_type", [KeyboardInterrupt, SystemExit, GeneratorExit])
async def test_child_cleanup_preserves_interpreter_control_flow(failure_type) -> None:
    """Never consume interpreter/process control flow at the child boundary."""
    stream = _DirectCleanupFailureStream(failure_type())

    with pytest.raises(failure_type):
        await transport_module._close_connection_stream_best_effort(stream)
