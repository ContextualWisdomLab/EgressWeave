"""Coverage for malformed outbound request-header tuple shapes."""

import pytest

from egressweave import EGRESS_NOT_ALLOWED, EgressNotAllowedError
from egressweave.request_safety import _enforce_request_header_limits


def test_request_header_limit_rejects_incomplete_field_tuple_generically() -> None:
    """Mask unpacking failures from malformed downstream metadata items."""
    with pytest.raises(
        EgressNotAllowedError,
        match=f"^{EGRESS_NOT_ALLOWED}$",
    ) as error:
        _enforce_request_header_limits(
            ((b"x-incomplete",),),  # type: ignore[arg-type]
            max_request_header_fields=10,
            max_request_header_bytes=1024,
        )

    assert error.value.__cause__ is None
