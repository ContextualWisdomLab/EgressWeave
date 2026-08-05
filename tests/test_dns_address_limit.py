"""Regression tests for finite DNS answer and connection-candidate cardinality."""

from __future__ import annotations

import socket

import pytest

from egressweave import (
    EgressNotAllowedError,
    EgressPolicy,
    build_egress_decision_evidence,
    validate_egress_url_details,
    validate_egress_url_details_async,
)
from egressweave import validation as validation_module
from egressweave.validation import _make_validated_egress_url

_PUBLIC_ADDRESSES = (
    "93.184.216.34",
    "1.1.1.1",
    "8.8.8.8",
)


def _install_address_answer(monkeypatch: pytest.MonkeyPatch, addresses: tuple[str, ...]) -> None:
    """Install one deterministic ordered platform-resolver answer."""

    def fake_getaddrinfo(host: str, port: int, type: int | None = None):
        return [
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (address, port))
            for address in addresses
        ]

    monkeypatch.setattr(validation_module.socket, "getaddrinfo", fake_getaddrinfo)


def test_policy_defaults_to_finite_resolved_address_limit() -> None:
    """Expose one finite default for DNS-derived connection candidates."""
    policy = EgressPolicy.from_hosts("api.example.com")

    assert policy.max_resolved_addresses == 16
    assert isinstance(policy.max_resolved_addresses, int)


def test_new_limit_preserves_existing_positional_constructor_order() -> None:
    """Append the new public field without reinterpreting legacy arguments."""
    policy = EgressPolicy(
        frozenset({"api.example.com"}),
        False,
        5.0,
        frozenset({8443}),
        frozenset({"GET"}),
        2048,
        None,
        1024,
    )

    assert policy.allowed_ports == frozenset({8443})
    assert policy.allowed_methods == frozenset({"GET"})
    assert policy.max_response_bytes == 2048
    assert policy.max_request_bytes == 1024
    assert policy.max_resolved_addresses == 16


@pytest.mark.parametrize(
    ("value", "error_type", "message"),
    [
        (0, ValueError, "^max_resolved_addresses must be greater than zero$"),
        (-1, ValueError, "^max_resolved_addresses must be greater than zero$"),
        ("", ValueError, "^max_resolved_addresses must be a positive decimal count$"),
        ("+2", ValueError, "^max_resolved_addresses must be a positive decimal count$"),
        ("２", ValueError, "^max_resolved_addresses must be a positive decimal count$"),
        (True, TypeError, "^max_resolved_addresses must be an integer count$"),
        (1.5, TypeError, "^max_resolved_addresses must be an integer count$"),
    ],
)
def test_policy_rejects_invalid_resolved_address_limit(
    value: object,
    error_type: type[Exception],
    message: str,
) -> None:
    """Reject configuration that could remove or ambiguously coerce the limit."""
    with pytest.raises(error_type, match=message):
        EgressPolicy.from_hosts(
            "api.example.com",
            max_resolved_addresses=value,
        )


def test_policy_normalizes_decimal_resolved_address_limit() -> None:
    """Accept an ASCII decimal string for environment-variable configuration."""
    policy = EgressPolicy.from_authorities(
        [("api.example.com", 443)],
        max_resolved_addresses="2",
    )

    assert policy.max_resolved_addresses == 2
    assert isinstance(policy.max_resolved_addresses, int)


def test_sync_validation_rejects_dns_answer_over_candidate_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Fail closed before returning an oversized set of pinned candidates."""
    _install_address_answer(monkeypatch, _PUBLIC_ADDRESSES)
    policy = EgressPolicy.from_hosts(
        "api.example.com",
        max_resolved_addresses=2,
    )

    with pytest.raises(EgressNotAllowedError, match="^egress URL is not allowed$"):
        validate_egress_url_details("https://api.example.com/v1", policy=policy)


async def test_async_validation_rejects_dns_answer_over_candidate_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Apply the same cardinality boundary through asynchronous validation."""
    _install_address_answer(monkeypatch, _PUBLIC_ADDRESSES)
    policy = EgressPolicy.from_hosts(
        "api.example.com",
        max_resolved_addresses=2,
    )

    with pytest.raises(EgressNotAllowedError, match="^egress URL is not allowed$"):
        await validate_egress_url_details_async(
            "https://api.example.com/v1",
            policy=policy,
        )


def test_unique_address_limit_preserves_order_and_ignores_duplicates(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Count unique validated addresses while preserving resolver preference order."""
    _install_address_answer(
        monkeypatch,
        (_PUBLIC_ADDRESSES[0], _PUBLIC_ADDRESSES[0], _PUBLIC_ADDRESSES[1]),
    )
    policy = EgressPolicy.from_hosts(
        "api.example.com",
        max_resolved_addresses=2,
    )

    validated = validate_egress_url_details(
        "https://api.example.com/v1",
        policy=policy,
    )

    assert validated is not None
    assert validated.addresses == _PUBLIC_ADDRESSES[:2]


def test_revalidation_rejects_signed_state_over_current_candidate_limit() -> None:
    """Prevent a wider prior validation result from entering a stricter transport."""
    validated = _make_validated_egress_url(
        "https://api.example.com/v1",
        "api.example.com",
        443,
        _PUBLIC_ADDRESSES,
    )
    policy = EgressPolicy.from_hosts(
        "api.example.com",
        max_resolved_addresses=2,
    )

    with pytest.raises(EgressNotAllowedError, match="^egress URL is not allowed$"):
        build_egress_decision_evidence(validated, policy=policy)


def test_resolved_address_limit_changes_audit_policy_fingerprint() -> None:
    """Make DNS candidate-budget drift visible without exposing resolved addresses."""
    validated = _make_validated_egress_url(
        "https://api.example.com/v1",
        "api.example.com",
        443,
        _PUBLIC_ADDRESSES[:2],
    )
    smaller = EgressPolicy.from_hosts(
        "api.example.com",
        max_resolved_addresses=2,
    )
    larger = EgressPolicy.from_hosts(
        "api.example.com",
        max_resolved_addresses=3,
    )

    smaller_evidence = build_egress_decision_evidence(validated, policy=smaller)
    larger_evidence = build_egress_decision_evidence(validated, policy=larger)

    assert smaller_evidence.policy_fingerprint != larger_evidence.policy_fingerprint
    assert smaller_evidence.decision_fingerprint != larger_evidence.decision_fingerprint
