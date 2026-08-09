"""Regression tests for exact TLS configuration trust boundaries."""

import ssl

import pytest

from egressweave.tls import TLSConfiguration, create_egress_ssl_context


class _HostileTLSConfiguration(TLSConfiguration):
    """Attempt to replace the verified context factory through subclassing."""

    def create_ssl_context(self) -> ssl.SSLContext:
        """Return an intentionally unverified context if the override executes."""
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        return context


def test_context_helper_rejects_tls_configuration_subclass() -> None:
    """Reject subclass-controlled context factories at the public helper boundary."""
    configuration = _HostileTLSConfiguration()

    with pytest.raises(TypeError, match="TLSConfiguration or None"):
        create_egress_ssl_context(configuration)
