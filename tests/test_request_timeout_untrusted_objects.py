"""Regression tests for hostile request-timeout extension objects."""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from numbers import Real

import pytest

from egressweave import EGRESS_NOT_ALLOWED, EgressNotAllowedError, EgressTimeoutPolicy
from egressweave.request_safety import _bind_bounded_request_timeouts


class _ExplodingTimeoutMapping(Mapping[str, object]):
    """Expose one key but raise when the timeout value is retrieved."""

    def __getitem__(self, key: str) -> object:
        """Raise caller-controlled failure text instead of returning a value."""
        raise RuntimeError("secret mapping failure")

    def __iter__(self) -> Iterator[str]:
        """Advertise one valid timeout phase key."""
        return iter(("connect",))

    def __len__(self) -> int:
        """Report the one advertised key."""
        return 1


class _ExplodingReal:
    """Behave as a registered real number whose conversion raises."""

    def __float__(self) -> float:
        """Raise caller-controlled failure text during numeric conversion."""
        raise RuntimeError("secret numeric failure")


Real.register(_ExplodingReal)


def _assert_generic_timeout_denial(timeout_value: object) -> None:
    """Require hostile timeout values to preserve the generic error boundary."""
    with pytest.raises(
        EgressNotAllowedError,
        match=f"^{EGRESS_NOT_ALLOWED}$",
    ) as error:
        _bind_bounded_request_timeouts(
            {"timeout": timeout_value},
            EgressTimeoutPolicy(),
        )

    assert error.value.__cause__ is None
    assert error.value.__context__ is None


def test_timeout_mapping_exceptions_are_masked() -> None:
    """Mask failures raised while copying an untrusted timeout mapping."""
    _assert_generic_timeout_denial(_ExplodingTimeoutMapping())


def test_timeout_numeric_conversion_exceptions_are_masked() -> None:
    """Mask failures raised while converting an untrusted real-number object."""
    _assert_generic_timeout_denial({"connect": _ExplodingReal()})
