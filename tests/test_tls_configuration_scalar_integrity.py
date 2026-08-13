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


class _HostilePasswordText(str):
    """Represent executable behavior hidden inside password text."""


class _HostilePasswordBytes(bytes):
    """Represent executable behavior hidden inside password bytes."""


class _HostilePasswordBuffer(bytearray):
    """Expose conversion of a mutable password subclass before retention."""

    def __bytes__(self) -> bytes:
        """Fail if trusted construction converts a polymorphic buffer."""
        raise AssertionError("TLS configuration invoked hostile password conversion")


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


@pytest.mark.parametrize(
    "password",
    [
        _HostilePasswordText("secret"),
        _HostilePasswordBytes(b"secret"),
        _HostilePasswordBuffer(b"secret"),
    ],
)
def test_private_key_password_rejects_builtin_subclasses_before_retention(
    password: object,
) -> None:
    """Keep polymorphic secret scalars outside immutable TLS identity state."""
    with pytest.raises(TypeError, match="client_private_key_password"):
        TLSConfiguration(
            client_certificate_file="identity/client.pem",
            client_private_key_password=password,  # type: ignore[arg-type]
        )


@pytest.mark.parametrize("password", ["secret", b"secret", bytearray(b"secret")])
def test_exact_private_key_password_scalars_remain_supported(password: object) -> None:
    """Preserve Python TLS loader password shapes while freezing bytearrays."""
    configuration = TLSConfiguration(
        client_certificate_file="identity/client.pem",
        client_private_key_password=password,  # type: ignore[arg-type]
    )

    expected = bytes(password) if type(password) is bytearray else password
    assert configuration.client_private_key_password == expected
    assert type(configuration.client_private_key_password) is type(expected)


def test_exact_tls_scalar_values_and_standard_paths_remain_supported() -> None:
    """Preserve reviewed exact values and ordinary pathlib integration."""
    password_callback = lambda: "secret"
    configuration = TLSConfiguration(
        ca_file=Path("trust/roots.pem"),
        ca_path="trust/roots",
        ca_data=b"deferred-der-certificate",
        client_certificate_file=Path("identity/client.pem"),
        client_private_key_file="identity/client.key",
        client_private_key_password=password_callback,
    )

    assert configuration.ca_file == "trust/roots.pem"
    assert configuration.ca_path == "trust/roots"
    assert configuration.ca_data == b"deferred-der-certificate"
    assert configuration.client_certificate_file == "identity/client.pem"
    assert configuration.client_private_key_file == "identity/client.key"
    assert configuration.client_private_key_password is password_callback
