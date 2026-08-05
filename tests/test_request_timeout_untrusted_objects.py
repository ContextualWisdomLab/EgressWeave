"""Regression tests for hostile request-timeout extension objects."""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from numbers import Real

import pytest

from egressweave import EGRESS_NOT_ALLOWED, EgressNotAllowedError, EgressTimeoutPolicy
from egressweave.request_safety import _bind_bounded_request_timeouts


class _ExplodingTimeoutMapping(Mapping[str, object]):
    """Expose one key but fail through the standard mapping lookup protocol."""

    def __getitem__(self, key: str) -> object:
        """Raise a caller-controlled lookup failure instead of returning a value."""
        raise KeyError("secret mapping failure")

    def __iter__(self) -> Iterator[str]:
        """Advertise one valid timeout phase key."""
        return iter(("connect",))

    def __len__(self) -> int:
        """Report the one advertised key."""
        return 1


class _ExplodingReal:
    """Behave as a registered real number whose conversion is unsupported."""

    def __float__(self) -> float:
        """Raise a standard numeric-conversion error with caller-controlled text."""
        raise TypeError("secret numeric failure")


class _ExplodingStringKey(str):
    """Raise caller-controlled text when tuple membership compares a key."""

    def __eq__(self, other: object) -> bool:
        """Raise instead of comparing this hostile string subclass."""
        raise RuntimeError("secret key comparison failure")

    def __hash__(self) -> int:
        """Preserve ordinary hashing so this object can remain a mapping key."""
        return str.__hash__(self)


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


def test_timeout_key_comparison_exceptions_are_masked() -> None:
    """Reject string subclasses before invoking hostile equality methods."""
    _assert_generic_timeout_denial({_ExplodingStringKey("connect"): 1.0})
