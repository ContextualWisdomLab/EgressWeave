"""Immutable, fail-closed TLS and mutual-TLS client configuration.

The public :class:`TLSConfiguration` value object creates a fresh verified
``ssl.SSLContext`` for each pinned transport. Callers can add private trust
anchors, replace the default trust store, provide a client certificate identity,
and choose an explicit TLS 1.2 or TLS 1.3 protocol floor without supplying a
mutable context that could be weakened after validation.
"""

from __future__ import annotations

import os
import ssl
from collections.abc import Callable
from dataclasses import dataclass, field

from httpx._config import create_ssl_context as _create_httpx_ssl_context

_TLS12_FORWARD_SECRET_CIPHERS = "ECDHE+AESGCM:ECDHE+CHACHA20"
_TLS_PROTOCOL_FLOORS = frozenset(
    {
        ssl.TLSVersion.TLSv1_2,
        ssl.TLSVersion.TLSv1_3,
    }
)

_PrivateKeyPassword = (
    str
    | bytes
    | bytearray
    | Callable[[], str | bytes | bytearray]
    | None
)


def _normalize_path(
    field_name: str,
    value: str | os.PathLike[str] | None,
) -> str | None:
    """Return one non-empty text path without expanding or resolving it."""
    if value is None:
        return None
    try:
        normalized = os.fspath(value)
    except TypeError as exc:
        raise TypeError(f"{field_name} must be a string or path-like object") from exc
    if not isinstance(normalized, str):
        raise TypeError(f"{field_name} must resolve to a text path")
    if not normalized.strip():
        raise ValueError(f"{field_name} must not be empty")
    return normalized


def _normalize_ca_data(value: str | bytes | None) -> str | bytes | None:
    """Return non-empty PEM text or DER bytes for a custom trust anchor."""
    if value is None:
        return None
    if isinstance(value, str):
        if not value.strip():
            raise ValueError("ca_data must not be empty")
        return value
    if isinstance(value, bytes):
        if not value:
            raise ValueError("ca_data must not be empty")
        return value
    raise TypeError("ca_data must be PEM text or DER bytes")


def _validate_private_key_password(password: _PrivateKeyPassword) -> None:
    """Reject password values that Python's TLS loader cannot consume safely."""
    if password is None or callable(password):
        return
    if isinstance(password, (str, bytes, bytearray)):
        return
    raise TypeError("client_private_key_password must be text, bytes, or a callable")


@dataclass(frozen=True, slots=True)
class TLSConfiguration:
    """Describe immutable verified TLS and optional mutual-TLS client settings.

    ``minimum_version`` accepts only :attr:`ssl.TLSVersion.TLSv1_3` (the secure
    default) or an explicit :attr:`ssl.TLSVersion.TLSv1_2` compatibility floor.
    Server certificate validation and hostname verification are always enabled.

    ``include_default_trust_store`` retains HTTPX's normal non-environment trust
    behavior. Set it to ``False`` only with at least one of ``ca_file``,
    ``ca_path``, or ``ca_data``. Custom authorities are additive when the default
    store remains enabled and exclusive when it is disabled.

    ``client_certificate_file`` enables mutual TLS. The private key can be in
    that PEM file or supplied separately through ``client_private_key_file``.
    An optional password may be text, bytes, a bytearray, or a zero-argument
    callable accepted by :meth:`ssl.SSLContext.load_cert_chain`. Mutable
    bytearrays are copied to immutable bytes during construction. Password
    values are deliberately excluded from representations and equality
    comparisons.
    """

    minimum_version: ssl.TLSVersion = ssl.TLSVersion.TLSv1_3
    include_default_trust_store: bool = True
    ca_file: str | os.PathLike[str] | None = None
    ca_path: str | os.PathLike[str] | None = None
    ca_data: str | bytes | None = None
    client_certificate_file: str | os.PathLike[str] | None = None
    client_private_key_file: str | os.PathLike[str] | None = None
    client_private_key_password: _PrivateKeyPassword = field(
        default=None,
        repr=False,
        compare=False,
    )

    def __post_init__(self) -> None:
        """Normalize trusted configuration and reject ambiguous security values."""
        if not isinstance(self.minimum_version, ssl.TLSVersion):
            raise TypeError("minimum_version must be an ssl.TLSVersion member")
        if self.minimum_version not in _TLS_PROTOCOL_FLOORS:
            raise ValueError("minimum_version must be TLS 1.2 or TLS 1.3")
        if type(self.include_default_trust_store) is not bool:
            raise TypeError("include_default_trust_store must be a boolean")

        for field_name in (
            "ca_file",
            "ca_path",
            "client_certificate_file",
            "client_private_key_file",
        ):
            object.__setattr__(
                self,
                field_name,
                _normalize_path(field_name, getattr(self, field_name)),
            )
        object.__setattr__(self, "ca_data", _normalize_ca_data(self.ca_data))
        _validate_private_key_password(self.client_private_key_password)
        if isinstance(self.client_private_key_password, bytearray):
            object.__setattr__(
                self,
                "client_private_key_password",
                bytes(self.client_private_key_password),
            )

        if not self.include_default_trust_store and not any(
            (self.ca_file, self.ca_path, self.ca_data)
        ):
            raise ValueError("custom-only trust requires at least one custom CA source")
        if self.client_certificate_file is None:
            if self.client_private_key_file is not None:
                raise ValueError(
                    "client_private_key_file requires client_certificate_file"
                )
            if self.client_private_key_password is not None:
                raise ValueError(
                    "client_private_key_password requires client_certificate_file"
                )

    def create_ssl_context(self) -> ssl.SSLContext:
        """Build a fresh verified client context from this immutable configuration."""
        if self.include_default_trust_store:
            context = _create_httpx_ssl_context(verify=True, trust_env=False)
        else:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

        context.minimum_version = self.minimum_version
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED

        if self.minimum_version is ssl.TLSVersion.TLSv1_2:
            context.set_ciphers(_TLS12_FORWARD_SECRET_CIPHERS)
        if any((self.ca_file, self.ca_path, self.ca_data)):
            context.load_verify_locations(
                cafile=self.ca_file,
                capath=self.ca_path,
                cadata=self.ca_data,
            )
        if self.client_certificate_file is not None:
            _load_client_identity(
                context,
                self.client_certificate_file,
                self.client_private_key_file,
                self.client_private_key_password,
            )
        return context


def _load_client_identity(
    context: ssl.SSLContext,
    certificate_file: str,
    private_key_file: str | None,
    password: _PrivateKeyPassword,
) -> None:
    """Load one client certificate and private key into a fresh TLS context."""
    context.load_cert_chain(
        certfile=certificate_file,
        keyfile=private_key_file,
        password=password,
    )


def create_egress_ssl_context(
    configuration: TLSConfiguration | None,
) -> ssl.SSLContext:
    """Create the default HTTPX context or a fresh configured enterprise context."""
    if configuration is None:
        return _create_httpx_ssl_context(verify=True, trust_env=False)
    if not isinstance(configuration, TLSConfiguration):
        raise TypeError("tls_configuration must be TLSConfiguration or None")
    return configuration.create_ssl_context()


__all__ = ["TLSConfiguration"]
