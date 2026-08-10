"""Regression contracts for the exact validated-result transport boundary."""

from __future__ import annotations

import pytest

from egressweave import (
    EgressNotAllowedError,
    EgressPolicy,
    ValidatedEgressURL,
    build_pinned_https_async_client,
    build_pinned_https_client,
)

POLICY = EgressPolicy.from_hosts("api.example.com")


class _HostileValidatedResult(ValidatedEgressURL):
    """Expose pre-type-check integrity-signature access through a descriptor."""

    @property
    def _integrity_signature(self) -> bytes:
        """Fail if transport validation reads subclass-controlled integrity state."""
        raise AssertionError("untrusted validated-result signature read")


def _hostile_result() -> ValidatedEgressURL:
    """Create a hostile subclass without invoking the factory-only constructor."""
    return object.__new__(_HostileValidatedResult)


def test_sync_builder_rejects_subclass_before_attribute_access() -> None:
    """Reject hostile sync input before any subclass-controlled field access."""
    with pytest.raises(EgressNotAllowedError):
        build_pinned_https_client(_hostile_result(), policy=POLICY)


def test_async_builder_rejects_subclass_before_attribute_access() -> None:
    """Reject hostile async input before any subclass-controlled field access."""
    with pytest.raises(EgressNotAllowedError):
        build_pinned_https_async_client(_hostile_result(), policy=POLICY)
