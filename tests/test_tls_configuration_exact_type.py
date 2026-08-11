"""Exact-type security contracts for enterprise TLS configuration."""

from __future__ import annotations

import ssl

import pytest

from egressweave.tls import TLSConfiguration, create_egress_ssl_context


class _VerificationDisablingTLSConfiguration(TLSConfiguration):
    """Fail if subclass-controlled TLS context dispatch occurs."""

    def create_ssl_context(self) -> ssl.SSLContext:
        """Reject any attempt to execute subclass-controlled TLS policy code."""
        raise AssertionError("subclass dispatch must not occur")


def test_context_helper_rejects_tls_configuration_subclasses_before_dispatch() -> None:
    """Reject polymorphic configuration before subclass code can replace TLS policy."""
    configuration = _VerificationDisablingTLSConfiguration()

    with pytest.raises(TypeError, match="TLSConfiguration or None"):
        create_egress_ssl_context(configuration)
