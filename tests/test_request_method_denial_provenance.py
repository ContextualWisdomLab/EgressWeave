"""Regression evidence for generic request-method denial provenance."""

from __future__ import annotations

import httpx
import pytest

from egressweave.policy import EgressPolicy
from egressweave.sync_transport import _PinnedEgressTransport
from egressweave.transport import _PinnedEgressAsyncTransport
from egressweave.validation import (
    EGRESS_NOT_ALLOWED,
    EgressNotAllowedError,
    _make_validated_egress_url,
)


def _validated_example_url():
    """Return one deterministic factory-issued validation result."""
    return _make_validated_egress_url(
        "https://api.example.com",
        "api.example.com",
        443,
        ("93.184.216.34",),
    )


def _assert_generic_denial_has_no_private_provenance(error: EgressNotAllowedError) -> None:
    """Require generic policy denial without parser exception chaining."""
    assert str(error) == EGRESS_NOT_ALLOWED
    assert error.__cause__ is None
    assert error.__context__ is None


def test_sync_invalid_method_denial_erases_normalization_provenance() -> None:
    """Reject invalid request syntax without exposing the normalization error."""
    policy = EgressPolicy.from_hosts("api.example.com")
    transport = _PinnedEgressTransport(_validated_example_url(), policy)
    try:
        request = httpx.Request("BAD METHOD", "https://api.example.com/")
        with pytest.raises(EgressNotAllowedError) as captured:
            transport._verify_request_target(request)
        _assert_generic_denial_has_no_private_provenance(captured.value)
    finally:
        transport.close()


@pytest.mark.asyncio
async def test_async_invalid_method_denial_erases_normalization_provenance() -> None:
    """Apply the same non-leaking method boundary to the async transport."""
    policy = EgressPolicy.from_hosts("api.example.com")
    transport = _PinnedEgressAsyncTransport(_validated_example_url(), policy)
    try:
        request = httpx.Request("BAD METHOD", "https://api.example.com/")
        with pytest.raises(EgressNotAllowedError) as captured:
            transport._verify_request_target(request)
        _assert_generic_denial_has_no_private_provenance(captured.value)
    finally:
        await transport.aclose()
