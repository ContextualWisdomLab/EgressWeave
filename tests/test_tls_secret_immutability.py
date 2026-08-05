"""Regression coverage for immutable TLS private-key password storage."""

from __future__ import annotations

from egressweave.tls import TLSConfiguration


def test_mutable_private_key_password_is_copied_to_immutable_bytes() -> None:
    """Prevent caller mutation from changing deferred TLS identity configuration."""
    source_password = bytearray(b"initial-secret")
    configuration = TLSConfiguration(
        client_certificate_file="client.pem",
        client_private_key_password=source_password,
    )

    source_password[:] = b"changed-secret"

    assert configuration.client_private_key_password == b"initial-secret"
