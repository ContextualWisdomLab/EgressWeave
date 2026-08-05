"""Tests for finite DNS destination-address cardinality."""

from __future__ import annotations

import socket

import pytest

from egressweave import (
    EGRESS_NOT_ALLOWED,
    EgressNotAllowedError,
    EgressPolicy,
    validate_egress_url_details,
    validate_egress_url_details_async,
)
from egressweave import validation as v
from egressweave.validation import (
    _make_validated_egress_url,
    _revalidate_pinned_egress_url,
)

_HOSTNAME = "api.example.com"
_URL = f"https://{_HOSTNAME}/v1"
_PUBLIC_ADDRESSES = (
    "93.184.216.34",
    "8.8.8.8",
    "1.1.1.1",
)


def _address_info(address: str, port: int) -> tuple[object, ...]:
    """Return one deterministic getaddrinfo-compatible public address row."""
    family = socket.AF_INET6 if ":" in address else socket.AF_INET
    return (family, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (address, port))


def _install_address_rows(monkeypatch: pytest.MonkeyPatch, *addresses: str) -> None:
    """Replace platform DNS with ordered deterministic address rows."""

    def fake_getaddrinfo(
        host: str,
        port: int,
        type: int | None = None,
    ) -> list[tuple[object, ...]]:
        """Return the configured rows without external DNS access."""
        assert host == _HOSTNAME
        assert type == socket.SOCK_STREAM
        return [_address_info(address, port) for address in addresses]

    monkeypatch.setattr(v.socket, "getaddrinfo", fake_getaddrinfo)


def test_policy_defaults_to_finite_dns_address_limit() -> None:
    """Keep ordinary integrations bounded without extra configuration."""
    policy = EgressPolicy.from_hosts(_HOSTNAME)

    assert policy.max_resolved_addresses == 32


def test_policy_constructors_normalize_dns_address_limit() -> None:
    """Expose one consistent environment-friendly setting on both builders."""
    from_hosts = EgressPolicy.from_hosts(
        _HOSTNAME,
        max_resolved_addresses=" 2 ",
    )
    from_authorities = EgressPolicy.from_authorities(
        [(_HOSTNAME, 443)],
        max_resolved_addresses=3,
    )

    assert from_hosts.max_resolved_addresses == 2
    assert from_authorities.max_resolved_addresses == 3


@pytest.mark.parametrize("invalid_value", [True, 1.5, None])
def test_policy_rejects_non_integer_dns_address_limits(invalid_value: object) -> None:
    """Reject values that could silently disable deterministic accounting."""
    with pytest.raises(
        TypeError,
        match="^max_resolved_addresses must be an integer address count$",
    ):
        EgressPolicy.from_hosts(
            _HOSTNAME,
            max_resolved_addresses=invalid_value,
        )


@pytest.mark.parametrize("invalid_value", ["", "+1", "1.0", "２"])
def test_policy_rejects_malformed_dns_address_limits(invalid_value: str) -> None:
    """Accept only ASCII decimal text from deployment configuration."""
    with pytest.raises(
        ValueError,
        match="^max_resolved_addresses must be a positive decimal address count$",
    ):
        EgressPolicy.from_hosts(
            _HOSTNAME,
            max_resolved_addresses=invalid_value,
        )


@pytest.mark.parametrize("invalid_value", [0, -1, "0"])
def test_policy_rejects_non_positive_dns_address_limits(invalid_value: object) -> None:
    """Prevent zero or negative values from becoming an unbounded sentinel."""
    with pytest.raises(
        ValueError,
        match="^max_resolved_addresses must be greater than zero$",
    ):
        EgressPolicy.from_hosts(
            _HOSTNAME,
            max_resolved_addresses=invalid_value,
        )


def test_sync_resolution_accepts_exact_unique_address_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Preserve resolver order when the unique candidate set exactly fits."""
    _install_address_rows(monkeypatch, *_PUBLIC_ADDRESSES[:2])
    policy = EgressPolicy.from_hosts(_HOSTNAME, max_resolved_addresses=2)

    validated = validate_egress_url_details(_URL, policy=policy)

    assert validated is not None
    assert validated.addresses == _PUBLIC_ADDRESSES[:2]


def test_duplicate_dns_rows_do_not_consume_unique_address_budget(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Count distinct validated destinations rather than platform duplicate rows."""
    _install_address_rows(
        monkeypatch,
        _PUBLIC_ADDRESSES[0],
        _PUBLIC_ADDRESSES[0],
        _PUBLIC_ADDRESSES[1],
        _PUBLIC_ADDRESSES[1],
    )
    policy = EgressPolicy.from_hosts(_HOSTNAME, max_resolved_addresses=2)

    validated = validate_egress_url_details(_URL, policy=policy)

    assert validated is not None
    assert validated.addresses == _PUBLIC_ADDRESSES[:2]


def test_sync_resolution_rejects_first_excess_unique_address_generically(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Reject the complete DNS result instead of silently truncating candidates."""
    _install_address_rows(monkeypatch, *_PUBLIC_ADDRESSES)
    policy = EgressPolicy.from_hosts(_HOSTNAME, max_resolved_addresses=2)

    with pytest.raises(EgressNotAllowedError) as error:
        validate_egress_url_details(_URL, policy=policy)

    assert str(error.value) == EGRESS_NOT_ALLOWED


async def test_async_resolution_rejects_excess_unique_addresses_generically(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Apply the same finite cardinality to asynchronous validation."""
    _install_address_rows(monkeypatch, *_PUBLIC_ADDRESSES)
    policy = EgressPolicy.from_hosts(_HOSTNAME, max_resolved_addresses=2)

    with pytest.raises(EgressNotAllowedError) as error:
        await validate_egress_url_details_async(_URL, policy=policy)

    assert str(error.value) == EGRESS_NOT_ALLOWED


def test_revalidation_applies_the_current_policy_address_limit() -> None:
    """Refuse signed results whose candidate set exceeds a tighter policy."""
    validated = _make_validated_egress_url(
        _URL,
        _HOSTNAME,
        443,
        _PUBLIC_ADDRESSES,
    )
    tighter_policy = EgressPolicy.from_hosts(
        _HOSTNAME,
        max_resolved_addresses=2,
    )

    with pytest.raises(EgressNotAllowedError) as error:
        _revalidate_pinned_egress_url(validated, tighter_policy)

    assert str(error.value) == EGRESS_NOT_ALLOWED
