"""Regression evidence for generic request-method denial provenance."""

from __future__ import annotations

from pathlib import Path

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

_REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
_REQUEST_METHOD_GUIDE = _REPOSITORY_ROOT / "docs" / "research" / "canonical-request-methods.md"
_CHANGELOG = _REPOSITORY_ROOT / "CHANGELOG.md"


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


def _normalized_document(path: Path) -> str:
    """Return documentation text with insignificant whitespace collapsed."""
    return " ".join(path.read_text(encoding="utf-8").split())


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


def test_request_method_guide_records_non_leaking_denial_provenance() -> None:
    """Keep the operator-facing request-method denial boundary explicit."""
    guide = _normalized_document(_REQUEST_METHOD_GUIDE)

    assert (
        "Malformed method denials are raised only after method normalization has "
        "left its exception context, so the caller-visible `EgressNotAllowedError` "
        "has neither a private cause nor a private context."
    ) in guide


def test_changelog_records_request_method_provenance_hardening() -> None:
    """Record the pre-release request-method diagnostic hardening."""
    changelog = _normalized_document(_CHANGELOG)

    assert (
        "Erase private request-method normalization exception provenance from "
        "caller-visible policy denials."
    ) in changelog
