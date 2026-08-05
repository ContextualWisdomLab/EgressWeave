"""Fail-closed contracts for hostile response-header iterators."""

from __future__ import annotations

import pytest

from egressweave.response_safety import _enforce_response_header_limits
from egressweave.validation import EGRESS_NOT_ALLOWED, EgressNotAllowedError


class _ExplodingHeaders:
    """Yield one valid field and then raise peer-controlled diagnostic text."""

    def __iter__(self):
        """Expose one field before simulating a malformed downstream iterator."""
        yield b"x-safe", b"value"
        raise RuntimeError("peer-controlled response-header iterator failure")


def test_response_header_iterator_failure_is_generic_and_context_free() -> None:
    """Mask downstream iteration failures behind the stable policy boundary."""
    with pytest.raises(
        EgressNotAllowedError,
        match=f"^{EGRESS_NOT_ALLOWED}$",
    ) as error:
        _enforce_response_header_limits(
            _ExplodingHeaders(),
            max_response_header_fields=10,
            max_response_header_bytes=1024,
        )

    assert error.value.__cause__ is None
    assert error.value.__context__ is None
