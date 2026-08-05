"""Regression tests for the explicit TLS 1.2 cipher-suite allowlist."""

from __future__ import annotations

from egressweave.tls import _TLS12_FORWARD_SECRET_CIPHERS

_EXPECTED_TLS12_CIPHERS = {
    "ECDHE-ECDSA-AES128-GCM-SHA256",
    "ECDHE-ECDSA-AES256-GCM-SHA384",
    "ECDHE-ECDSA-CHACHA20-POLY1305",
    "ECDHE-RSA-AES128-GCM-SHA256",
    "ECDHE-RSA-AES256-GCM-SHA384",
    "ECDHE-RSA-CHACHA20-POLY1305",
}


def test_tls12_policy_uses_only_explicit_named_cipher_suites() -> None:
    """Prevent OpenSSL selector expansion from admitting future cipher families."""
    configured_ciphers = _TLS12_FORWARD_SECRET_CIPHERS.split(":")

    assert set(configured_ciphers) == _EXPECTED_TLS12_CIPHERS
    assert len(configured_ciphers) == len(_EXPECTED_TLS12_CIPHERS)
    assert all("+" not in cipher_name for cipher_name in configured_ciphers)
