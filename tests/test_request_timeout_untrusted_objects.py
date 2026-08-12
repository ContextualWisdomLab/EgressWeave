"""Regression tests for hostile request-timeout extension objects."""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from numbers import Real
from typing import NoReturn

import pytest

from egressweave import EGRESS_NOT_ALLOWED, EgressNotAllowedError, EgressTimeoutPolicy
from egressweave.request_safety import _bind_bounded_request_timeouts


def _raise_unexpected_protocol_failure(message: str) -> NoReturn:
    """Raise one arbitrary secret-bearing failure from untrusted protocol code."""
    raise RuntimeError(message)


class _ExplodingTimeoutMapping(Mapping[str, object]):
    """Expose one key but raise arbitrarily when its value is retrieved."""

    def __getitem__(self, key: str) -> object:
        """Delegate to an unexpected caller-controlled protocol failure."""
        return _raise_unexpected_protocol_failure("secret mapping failure")

    def __iter__(self) -> Iterator[str]:
        """Advertise one valid timeout phase key."""
        return iter(("connect",))

    def __len__(self) -> int:
        """Report the one advertised key."""
        return 1


class _ExplodingExtensionsCopyMapping(Mapping[str, object]):
    """Raise while the untrusted outer request-extension mapping is detached."""

    def __getitem__(self, key: str) -> object:
        """Delegate indexed access to an unexpected secret-bearing failure."""
        del key
        return _raise_unexpected_protocol_failure("secret extensions copy failure")

    def __iter__(self) -> Iterator[str]:
        """Advertise one ordinary reviewed extension key."""
        return iter(("timeout",))

    def __len__(self) -> int:
        """Report the one advertised extension key."""
        return 1


class _ExplodingExtensionsGetMapping(Mapping[str, object]):
    """Expose safe items while making direct ``get`` dispatch attacker-controlled."""

    def __getitem__(self, key: str) -> object:
        """Return one ordinary timeout mapping through indexed access."""
        if key == "timeout":
            return {"connect": 1.0}
        raise KeyError(key)

    def __iter__(self) -> Iterator[str]:
        """Advertise the single reviewed request-extension key."""
        return iter(("timeout",))

    def __len__(self) -> int:
        """Report the one advertised extension key."""
        return 1

    def get(self, key: str, default: object = None) -> object:
        """Raise if production code dynamically dispatches untrusted ``get``."""
        del key, default
        return _raise_unexpected_protocol_failure("secret extensions get failure")


class _ExplodingReal:
    """Behave as a registered real number whose conversion raises arbitrarily."""

    def __float__(self) -> float:
        """Delegate to an unexpected caller-controlled conversion failure."""
        return _raise_unexpected_protocol_failure("secret numeric failure")


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


def test_request_extension_copy_exceptions_are_masked() -> None:
    """Mask arbitrary failures while detaching the outer extension mapping."""
    with pytest.raises(
        EgressNotAllowedError,
        match=f"^{EGRESS_NOT_ALLOWED}$",
    ) as error:
        _bind_bounded_request_timeouts(
            _ExplodingExtensionsCopyMapping(),
            EgressTimeoutPolicy(),
        )

    assert error.value.__cause__ is None
    assert error.value.__context__ is None


def test_request_extensions_get_is_not_dynamically_dispatched() -> None:
    """Snapshot a valid outer mapping without invoking its hostile ``get`` method."""
    bounded = _bind_bounded_request_timeouts(
        _ExplodingExtensionsGetMapping(),
        EgressTimeoutPolicy(),
    )

    assert bounded["timeout"] == {
        "connect": 1.0,
        "read": 5.0,
        "write": 5.0,
        "pool": 5.0,
    }


def test_timeout_mapping_exceptions_are_masked() -> None:
    """Mask arbitrary failures raised while copying an untrusted timeout mapping."""
    _assert_generic_timeout_denial(_ExplodingTimeoutMapping())


def test_timeout_numeric_conversion_exceptions_are_masked() -> None:
    """Mask arbitrary failures from an untrusted real-number conversion method."""
    _assert_generic_timeout_denial({"connect": _ExplodingReal()})


def test_timeout_key_comparison_exceptions_are_masked() -> None:
    """Reject string subclasses before invoking hostile equality methods."""
    _assert_generic_timeout_denial({_ExplodingStringKey("connect"): 1.0})
