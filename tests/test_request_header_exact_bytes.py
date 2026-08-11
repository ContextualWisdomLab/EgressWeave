"""Regression tests for exact built-in request-header byte objects."""

from __future__ import annotations

import pytest

from egressweave import EGRESS_NOT_ALLOWED, EgressNotAllowedError
from egressweave.request_safety import _build_safe_request_headers


class _HostileHeaderBytes(bytes):
    """Fail if request-header validation executes subclass behavior."""

    def __len__(self) -> int:
        """Reject truthiness or resource accounting through this subclass."""
        raise AssertionError("header bytes subclass length executed")

    def __iter__(self):
        """Reject field-name octet iteration through this subclass."""
        raise AssertionError("header bytes subclass iteration executed")

    def __getitem__(self, key):
        """Reject field-value slicing through this subclass."""
        raise IndexError("header bytes subclass indexing executed")

    def lower(self):
        """Reject case normalization through this subclass."""
        raise AssertionError("header bytes subclass lower executed")


@pytest.mark.parametrize(
    "headers",
    (
        ((_HostileHeaderBytes(b"X-Test"), b"value"),),
        ((b"X-Test", _HostileHeaderBytes(b"value")),),
    ),
)
def test_safe_header_builder_rejects_bytes_subclasses_before_custom_behavior(
    headers: tuple[tuple[bytes, bytes], ...],
) -> None:
    """Reject header subclasses before invoking attacker-controlled protocols."""
    with pytest.raises(
        EgressNotAllowedError,
        match=f"^{EGRESS_NOT_ALLOWED}$",
    ) as exc_info:
        _build_safe_request_headers(headers, b"api.openai.com")

    assert exc_info.value.__cause__ is None
    assert exc_info.value.__context__ is None
