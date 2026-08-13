"""Regression coverage for exact TLS trust and identity scalar values."""

from __future__ import annotations

from pathlib import Path

import pytest

from egressweave.tls import TLSConfiguration


class _HostileText(str):
    """Expose any subclass-controlled text normalization at the TLS boundary."""

    def strip(self, *args: object, **kwargs: object) -> str:
        """Fail if trusted configuration invokes this polymorphic method."""
        del args, kwargs
        raise AssertionError("TLS configuration invoked hostile text normalization")


class _HostileBytes(bytes):
    """Expose any subclass-controlled truth-value check on CA bytes."""

    def __len__(self) -> int:
        """Fail if trusted configuration inspects polymorphic byte length."""
        raise AssertionError("TLS configuration invoked hostile byte length")


class _HostileTextPath:
    """Return a non-exact text path from the standard path protocol."""

    def __fspath__(self) -> str:
        """Return a text subclass that must be rejected before use."""
        return _HostileText("trust/private-ca.pem")


@pytest.mark.parametrize(
    "field_name",
    [
        "ca_file",
        "ca_path",
        "client_certificate_file",
        "client_private_key_file",
    ],
)
def test_tls_paths_reject_direct_text_subclasses_before_normalization(
    field_name: str,
) -> None:
    """Require exact path text before any subclass-defined text method runs."""
    with pytest.raises(TypeError, match="text path"):
        TLSConfiguration(**{field_name: _HostileText("identity.pem")})  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "field_name",
    [
        "ca_file",
        "ca_path",
        "client_certificate_file",
        "client_private_key_file",
    ],
)
def test_tls_paths_reject_pathlike_text_subclasses_before_normalization(
    field_name: str,
) -> None:
    """Detach one path-protocol value but reject a polymorphic text result."""
    with pytest.raises(TypeError, match="text path"):
        TLSConfiguration(**{field_name: _HostileTextPath()})  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "ca_data",
    [
        _HostileText("-----BEGIN CERTIFICATE-----"),
        _HostileBytes(b"deferred-der-certificate"),
    ],
)
def test_ca_data_rejects_builtin_subclasses_before_inspection(ca_data: object) -> None:
    """Keep polymorphic text or bytes outside immutable trust state."""
    with pytest.raises(TypeError, match="ca_data"):
        TLSConfiguration(ca_data=ca_data)  # type: ignore[arg-type]


def test_exact_tls_scalar_values_and_standard_paths_remain_supported() -> None:
    """Preserve reviewed exact values and ordinary pathlib integration."""
    configuration = TLSConfiguration(
        ca_file=Path("trust/roots.pem"),
        ca_path="trust/roots",
        ca_data=b"deferred-der-certificate",
        client_certificate_file=Path("identity/client.pem"),
        client_private_key_file="identity/client.key",
        client_private_key_password=lambda: "secret",
    )

    assert configuration.ca_file == "trust/roots.pem"
    assert configuration.ca_path == "trust/roots"
    assert configuration.ca_data == b"deferred-der-certificate"
    assert configuration.client_certificate_file == "identity/client.pem"
    assert configuration.client_private_key_file == "identity/client.key"
