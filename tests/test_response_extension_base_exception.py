"""Regression tests for response-extension lookup control-flow boundaries."""

from __future__ import annotations

import pytest

from egressweave import EgressNotAllowedError, response_safety


class _ExtensionLookupBaseException(BaseException):
    """Represent a dependency-controlled non-Exception lookup failure."""


class _HostileExtensionKey:
    """Collide with a reviewed key and raise one configured lookup failure."""

    def __init__(self, failure: BaseException) -> None:
        """Store the failure raised during dictionary equality."""
        self._failure = failure

    def __hash__(self) -> int:
        """Collide with the reviewed HTTP-version extension key."""
        return hash("http_version")

    def __eq__(self, other: object) -> bool:
        """Raise the configured dependency-controlled lookup failure."""
        raise self._failure


def test_response_extension_lookup_contains_custom_base_exception() -> None:
    """Convert dependency-controlled direct BaseException lookup failure to denial."""
    extensions = {
        _HostileExtensionKey(
            _ExtensionLookupBaseException("sensitive response extension failure")
        ): b"unreachable"
    }

    with pytest.raises(EgressNotAllowedError, match="^egress URL is not allowed$") as caught:
        response_safety._select_public_response_extensions(extensions)

    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None


@pytest.mark.parametrize("failure_type", [KeyboardInterrupt, SystemExit, GeneratorExit])
def test_response_extension_lookup_preserves_interpreter_control_flow(
    failure_type: type[BaseException],
) -> None:
    """Never consume interpreter or process control flow at the lookup boundary."""
    extensions = {_HostileExtensionKey(failure_type()): b"unreachable"}

    with pytest.raises(failure_type):
        response_safety._select_public_response_extensions(extensions)
