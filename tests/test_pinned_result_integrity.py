"""Regression tests for forged or tampered validation results."""

import pytest

from egressweave import (
    EgressNotAllowedError,
    EgressPolicy,
    ValidatedEgressURL,
    build_pinned_https_async_client,
    validate_egress_url_details,
)
from egressweave import validation as v

POLICY = EgressPolicy.from_hosts("api.openai.com")


class _HostileValidatedResult(ValidatedEgressURL):
    """Expose pre-type-check integrity-signature access through a test descriptor."""

    @property
    def _integrity_signature(self) -> bytes:
        """Fail if validation reads subclass-controlled integrity state."""
        raise AssertionError("untrusted validated-result signature read")


def _forge_untrusted_result() -> ValidatedEgressURL:
    validated = object.__new__(ValidatedEgressURL)
    object.__setattr__(validated, "normalized_url", "https://api.openai.com")
    object.__setattr__(validated, "hostname", "api.openai.com")
    object.__setattr__(validated, "port", 443)
    object.__setattr__(validated, "addresses", ("93.184.216.34",))
    return validated


def _validated_result(monkeypatch) -> ValidatedEgressURL:
    def fake_getaddrinfo(host, port, type=None):
        return [(2, 1, 6, "", ("93.184.216.34", port))]

    monkeypatch.setattr(v.socket, "getaddrinfo", fake_getaddrinfo)
    validated = validate_egress_url_details(
        "https://api.openai.com", policy=POLICY
    )
    assert validated is not None
    return validated


def test_validated_result_constructor_is_factory_only() -> None:
    with pytest.raises(TypeError):
        ValidatedEgressURL(
            "https://api.openai.com",
            "api.openai.com",
            443,
            ("93.184.216.34",),
        )


def test_build_pinned_client_rejects_untrusted_result() -> None:
    with pytest.raises(EgressNotAllowedError):
        build_pinned_https_async_client(_forge_untrusted_result(), policy=POLICY)


def test_build_pinned_client_rejects_subclass_before_attribute_access() -> None:
    hostile_result = object.__new__(_HostileValidatedResult)

    with pytest.raises(EgressNotAllowedError):
        build_pinned_https_async_client(hostile_result, policy=POLICY)


@pytest.mark.parametrize(
    "field_name, replacement",
    [
        ("normalized_url", "https://evil.example"),
        ("normalized_url", "http://api.openai.com"),
        ("normalized_url", "https://api.openai.com/v2"),
        ("hostname", "api.anthropic.com"),
        ("port", 8443),
        ("addresses", ["93.184.216.34"]),
        ("addresses", ("10.0.0.1",)),
        ("addresses", ("8.8.8.8",)),
        ("_integrity_signature", b"forged"),
    ],
    ids=[
        "host-not-allowlisted",
        "remote-plaintext-http",
        "url-path-integrity",
        "url-hostname-mismatch",
        "url-port-mismatch",
        "address-container-shape",
        "address-scope",
        "public-address-integrity",
        "signature-integrity",
    ],
)
def test_build_pinned_client_rejects_tampered_trusted_result(
    monkeypatch, field_name: str, replacement: object
) -> None:
    validated = _validated_result(monkeypatch)
    object.__setattr__(validated, field_name, replacement)

    with pytest.raises(EgressNotAllowedError):
        build_pinned_https_async_client(validated, policy=POLICY)
