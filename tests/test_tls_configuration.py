"""Security contracts for immutable enterprise TLS client configuration."""

from __future__ import annotations

import ssl
from importlib import import_module
from pathlib import Path
from types import SimpleNamespace

import certifi
import pytest

from egressweave import sync_transport as sync_transport_module
from egressweave import transport as async_transport_module
from egressweave.tls import (
    TLSConfiguration,
    _load_client_identity,
    create_egress_ssl_context,
)


def _first_certifi_certificate() -> str:
    """Return one valid PEM trust anchor from the installed certifi bundle."""
    bundle = Path(certifi.where()).read_text(encoding="ascii")
    certificate, separator, _ = bundle.partition("-----END CERTIFICATE-----")
    assert separator
    return f"{certificate}{separator}\n"


def test_default_configuration_builds_verified_tls13_context() -> None:
    """Use TLS 1.3, hostname checks, and certificate validation by default."""
    secret_configuration = TLSConfiguration(
        client_certificate_file="client.pem",
        client_private_key_password="redacted-secret",
    )
    safe_configuration = TLSConfiguration()

    context = safe_configuration.create_ssl_context()

    assert context.minimum_version is ssl.TLSVersion.TLSv1_3
    assert context.check_hostname is True
    assert context.verify_mode is ssl.CERT_REQUIRED
    assert context.get_ca_certs()
    assert "redacted-secret" not in repr(secret_configuration)


def test_configuration_supports_explicit_tls12_compatibility() -> None:
    """Allow only forward-secret ECDHE suites under a TLS 1.2 floor."""
    configuration = TLSConfiguration(minimum_version=ssl.TLSVersion.TLSv1_2)

    context = configuration.create_ssl_context()
    tls12_ciphers = [
        cipher for cipher in context.get_ciphers() if cipher["protocol"] == "TLSv1.2"
    ]

    assert context.minimum_version is ssl.TLSVersion.TLSv1_2
    assert context.check_hostname is True
    assert context.verify_mode is ssl.CERT_REQUIRED
    assert tls12_ciphers
    assert all(cipher["kea"] == "kx-ecdhe" for cipher in tls12_ciphers)
    assert all(cipher["auth"] in {"auth-rsa", "auth-ecdsa"} for cipher in tls12_ciphers)


@pytest.mark.parametrize(
    "minimum_version",
    [
        ssl.TLSVersion.MINIMUM_SUPPORTED,
        ssl.TLSVersion.TLSv1,
        ssl.TLSVersion.TLSv1_1,
        ssl.TLSVersion.MAXIMUM_SUPPORTED,
    ],
)
def test_configuration_rejects_obsolete_or_ambiguous_tls_floors(
    minimum_version: ssl.TLSVersion,
) -> None:
    """Accept only explicit TLS 1.2 or TLS 1.3 protocol floors."""
    with pytest.raises(ValueError, match="TLS 1.2 or TLS 1.3"):
        TLSConfiguration(minimum_version=minimum_version)


@pytest.mark.parametrize("minimum_version", [True, 3, "TLSv1.3", object()])
def test_configuration_rejects_non_enum_tls_floors(minimum_version: object) -> None:
    """Reject values that are not actual ``ssl.TLSVersion`` members."""
    with pytest.raises(TypeError, match="minimum_version"):
        TLSConfiguration(minimum_version=minimum_version)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("field_name", "field_value", "error_type"),
    [
        ("include_default_trust_store", "false", TypeError),
        ("ca_file", "   ", ValueError),
        ("ca_path", b"/tmp/ca", TypeError),
        ("ca_data", "", ValueError),
        ("ca_data", b"", ValueError),
        ("ca_data", bytearray(b"certificate"), TypeError),
        ("client_certificate_file", "", ValueError),
        ("client_private_key_file", b"/tmp/key", TypeError),
    ],
)
def test_configuration_rejects_ambiguous_trust_and_identity_values(
    field_name: str,
    field_value: object,
    error_type: type[Exception],
) -> None:
    """Fail at construction instead of coercing security-sensitive values."""
    with pytest.raises(error_type):
        TLSConfiguration(**{field_name: field_value})  # type: ignore[arg-type]


def test_path_normalization_rejects_non_pathlike_and_binary_pathlike_values() -> None:
    """Reject objects and path protocols that do not produce deterministic text."""

    class BinaryPath:
        """Return a binary path to exercise the text-path contract."""

        def __fspath__(self) -> bytes:
            """Return a value that security configuration must reject."""
            return b"trust/roots.pem"

    with pytest.raises(TypeError, match="string or path-like"):
        TLSConfiguration(ca_file=object())  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="text path"):
        TLSConfiguration(ca_file=BinaryPath())  # type: ignore[arg-type]


def test_custom_only_trust_requires_and_loads_an_explicit_authority() -> None:
    """Build an isolated trust store only when at least one CA source is present."""
    with pytest.raises(ValueError, match="custom CA source"):
        TLSConfiguration(include_default_trust_store=False)

    configuration = TLSConfiguration(
        include_default_trust_store=False,
        ca_data=_first_certifi_certificate(),
    )
    context = configuration.create_ssl_context()

    assert context.minimum_version is ssl.TLSVersion.TLSv1_3
    assert context.check_hostname is True
    assert context.verify_mode is ssl.CERT_REQUIRED
    assert len(context.get_ca_certs()) == 1


def test_default_and_custom_trust_are_additive() -> None:
    """Retain public roots while adding an integration-specific trust anchor."""
    configuration = TLSConfiguration(ca_data=_first_certifi_certificate())

    context = configuration.create_ssl_context()

    assert len(context.get_ca_certs()) > 1


def test_binary_ca_data_is_preserved_for_deferred_ssl_validation() -> None:
    """Accept non-empty DER bytes without parsing application configuration early."""
    configuration = TLSConfiguration(ca_data=b"deferred-der-validation")

    assert configuration.ca_data == b"deferred-der-validation"


def test_pathlike_values_are_normalized_without_expanding_or_resolving() -> None:
    """Store deterministic text paths while leaving filesystem access to build time."""
    configuration = TLSConfiguration(
        ca_file=Path("trust/roots.pem"),
        ca_path=Path("trust/directory"),
        client_certificate_file=Path("identity/client.pem"),
        client_private_key_file=Path("identity/client.key"),
        client_private_key_password=lambda: "secret",
    )

    assert configuration.ca_file == "trust/roots.pem"
    assert configuration.ca_path == "trust/directory"
    assert configuration.client_certificate_file == "identity/client.pem"
    assert configuration.client_private_key_file == "identity/client.key"
    assert "secret" not in repr(configuration)


@pytest.mark.parametrize(
    "password",
    ["secret", b"secret", bytearray(b"secret"), lambda: "secret"],
)
def test_supported_client_key_password_types_are_secret_safe(password) -> None:
    """Accept SSL-supported password values without exposing them in representation."""
    configuration = TLSConfiguration(
        client_certificate_file="client.pem",
        client_private_key_password=password,
    )

    assert "secret" not in repr(configuration)


def test_configuration_rejects_unsupported_client_key_password_type() -> None:
    """Reject password objects that the SSL certificate loader cannot consume."""
    with pytest.raises(TypeError, match="client_private_key_password"):
        TLSConfiguration(
            client_certificate_file="client.pem",
            client_private_key_password=object(),  # type: ignore[arg-type]
        )


def test_client_key_and_password_require_a_certificate() -> None:
    """Reject incomplete mTLS identity configuration before filesystem access."""
    with pytest.raises(ValueError, match="client_certificate_file"):
        TLSConfiguration(client_private_key_file="client.key")
    with pytest.raises(ValueError, match="client_certificate_file"):
        TLSConfiguration(client_private_key_password="secret")


def test_client_identity_is_loaded_into_the_fresh_context(monkeypatch) -> None:
    """Pass the configured certificate, key, and hidden password to the TLS context."""
    observed: dict[str, object] = {}

    def capture_identity(
        context: ssl.SSLContext,
        certificate_file: str,
        private_key_file: str | None,
        password,
    ) -> None:
        observed.update(
            context=context,
            certificate_file=certificate_file,
            private_key_file=private_key_file,
            password=password,
        )

    monkeypatch.setattr("egressweave.tls._load_client_identity", capture_identity)
    password = lambda: "secret"
    configuration = TLSConfiguration(
        client_certificate_file="client.pem",
        client_private_key_file="client.key",
        client_private_key_password=password,
    )

    context = configuration.create_ssl_context()

    assert observed == {
        "context": context,
        "certificate_file": "client.pem",
        "private_key_file": "client.key",
        "password": password,
    }


def test_client_identity_loader_preserves_ssl_file_errors(tmp_path: Path) -> None:
    """Surface trusted startup configuration errors without weakening TLS policy."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

    with pytest.raises(FileNotFoundError):
        _load_client_identity(
            context,
            str(tmp_path / "missing-client.pem"),
            None,
            None,
        )


def test_default_helper_preserves_existing_httpx_trust_behavior() -> None:
    """Keep existing callers unchanged while opt-in configuration is stricter."""
    default_context = create_egress_ssl_context(None)
    configured_context = create_egress_ssl_context(TLSConfiguration())

    assert default_context.check_hostname is True
    assert default_context.verify_mode is ssl.CERT_REQUIRED
    assert configured_context.minimum_version is ssl.TLSVersion.TLSv1_3
    assert configured_context is not default_context


def test_context_helper_rejects_mutable_or_unknown_configuration() -> None:
    """Refuse caller-owned contexts and unrelated values at the trust boundary."""
    with pytest.raises(TypeError, match="TLSConfiguration or None"):
        create_egress_ssl_context(object())  # type: ignore[arg-type]


def test_sync_transport_uses_the_injected_fresh_context(monkeypatch) -> None:
    """Thread enterprise TLS configuration into the pinned synchronous pool."""
    configuration = TLSConfiguration()
    expected_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    validated = SimpleNamespace(
        normalized_url="https://api.example.com",
        hostname="api.example.com",
        port=443,
        addresses=("93.184.216.34",),
    )
    observed: dict[str, object] = {}

    monkeypatch.setattr(
        sync_transport_module,
        "_revalidate_pinned_egress_url",
        lambda value, policy: validated,
    )
    monkeypatch.setattr(
        sync_transport_module,
        "create_egress_ssl_context",
        lambda value: observed.update(configuration=value) or expected_context,
    )
    monkeypatch.setattr(
        sync_transport_module,
        "_PinnedEgressSyncNetworkBackend",
        lambda *args, **kwargs: object(),
    )

    class FakePool:
        """Capture connection-pool construction without opening sockets."""

        def __init__(self, **kwargs) -> None:
            observed.update(kwargs)

        def close(self) -> None:
            """Close the inert test pool."""

    monkeypatch.setattr(sync_transport_module.httpcore, "ConnectionPool", FakePool)

    transport = sync_transport_module._PinnedEgressTransport(
        object(),
        sync_transport_module.EgressPolicy.from_hosts("api.example.com"),
        tls_configuration=configuration,
    )
    transport.close()

    assert observed["configuration"] is configuration
    assert observed["ssl_context"] is expected_context


@pytest.mark.asyncio
async def test_async_transport_uses_the_injected_fresh_context(monkeypatch) -> None:
    """Thread enterprise TLS configuration into the pinned asynchronous pool."""
    configuration = TLSConfiguration()
    expected_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    validated = SimpleNamespace(
        normalized_url="https://api.example.com",
        hostname="api.example.com",
        port=443,
        addresses=("93.184.216.34",),
    )
    observed: dict[str, object] = {}

    monkeypatch.setattr(
        async_transport_module,
        "_revalidate_pinned_egress_url",
        lambda value, policy: validated,
    )
    monkeypatch.setattr(
        async_transport_module,
        "create_egress_ssl_context",
        lambda value: observed.update(configuration=value) or expected_context,
    )
    monkeypatch.setattr(
        async_transport_module,
        "_PinnedEgressNetworkBackend",
        lambda *args, **kwargs: object(),
    )

    class FakePool:
        """Capture asynchronous pool construction without opening sockets."""

        def __init__(self, **kwargs) -> None:
            observed.update(kwargs)

        async def aclose(self) -> None:
            """Close the inert test pool."""

    monkeypatch.setattr(async_transport_module.httpcore, "AsyncConnectionPool", FakePool)

    transport = async_transport_module._PinnedEgressAsyncTransport(
        object(),
        async_transport_module.EgressPolicy.from_hosts("api.example.com"),
        tls_configuration=configuration,
    )
    await transport.aclose()

    assert observed["configuration"] is configuration
    assert observed["ssl_context"] is expected_context


def test_public_builders_accept_tls_configuration_keyword(monkeypatch) -> None:
    """Expose one consistent TLS injection keyword across all public builders."""
    configuration = TLSConfiguration()
    validated = SimpleNamespace(normalized_url="https://api.example.com")
    observed: list[object] = []

    monkeypatch.setattr(
        sync_transport_module,
        "validate_egress_url_details",
        lambda value, policy: validated,
    )
    monkeypatch.setattr(
        sync_transport_module,
        "_PinnedEgressTransport",
        lambda value, policy, *, tls_configuration=None: observed.append(
            tls_configuration
        )
        or object(),
    )
    normalized_url, client = sync_transport_module.build_egress_sync_client(
        "https://api.example.com",
        policy=sync_transport_module.EgressPolicy.from_hosts("api.example.com"),
        tls_configuration=configuration,
    )
    client.close()

    assert normalized_url == "https://api.example.com"
    assert observed == [configuration]


def test_public_package_exports_tls_configuration() -> None:
    """Expose the enterprise TLS contract through the stable package surface."""
    package = import_module("egressweave")

    assert package.TLSConfiguration is TLSConfiguration
    assert "TLSConfiguration" in package.__all__
