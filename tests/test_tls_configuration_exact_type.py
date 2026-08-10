"""Exact-type security contracts for enterprise TLS configuration."""

from __future__ import annotations

import ssl

import pytest

from egressweave.tls import TLSConfiguration, create_egress_ssl_context


class _VerificationDisablingTLSConfiguration(TLSConfiguration):
    """Return an insecure context if subclass-controlled dispatch is allowed."""

    def create_ssl_context(self) -> ssl.SSLContext:
        """Build a context that deliberately violates the EgressWeave TLS contract."""
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        return context


def test_context_helper_rejects_tls_configuration_subclasses_before_dispatch() -> None:
    """Reject polymorphic configuration before subclass code can replace TLS policy."""
    configuration = _VerificationDisablingTLSConfiguration()

    with pytest.raises(TypeError, match="TLSConfiguration or None"):
        create_egress_ssl_context(configuration)
