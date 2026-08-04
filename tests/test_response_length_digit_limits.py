"""Regression coverage for pathological decimal response lengths."""

import pytest

from egressweave import EgressNotAllowedError
from egressweave.response_safety import _enforce_declared_response_size


@pytest.mark.parametrize("declared_length", [b"0", b"0004"])
def test_declared_response_size_accepts_zero_and_leading_zero_lengths(
    declared_length: bytes,
) -> None:
    """Preserve valid decimal semantics without converting the field to int."""
    _enforce_declared_response_size(
        "GET",
        200,
        ((b"Content-Length", declared_length),),
        4,
    )


def test_declared_response_size_rejects_pathological_decimal_length_generically() -> None:
    """Reject arbitrarily long digit fields without leaking Python int errors."""
    with pytest.raises(EgressNotAllowedError, match="^egress URL is not allowed$"):
        _enforce_declared_response_size(
            "GET",
            200,
            ((b"Content-Length", b"9" * 5000),),
            4,
        )
