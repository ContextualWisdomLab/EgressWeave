"""Regression tests for version-stable special-purpose address classification."""

from __future__ import annotations

import ipaddress

import pytest

from egressweave import EgressPolicy
from egressweave.validation import EgressNotAllowedError, _validate_global_address

_REMOTE_POLICY = EgressPolicy.from_hosts("api.example.com")


def _force_address_properties(
    monkeypatch: pytest.MonkeyPatch,
    address_type: type[ipaddress.IPv4Address | ipaddress.IPv6Address],
    *,
    private: bool,
    global_: bool,
) -> None:
    """Replace version-sensitive stdlib address properties for one test."""
    monkeypatch.setattr(address_type, "is_private", property(lambda self: private))
    monkeypatch.setattr(address_type, "is_global", property(lambda self: global_))
    monkeypatch.setattr(address_type, "is_loopback", property(lambda self: False))
    monkeypatch.setattr(address_type, "is_link_local", property(lambda self: False))
    monkeypatch.setattr(address_type, "is_reserved", property(lambda self: False))
    monkeypatch.setattr(address_type, "is_unspecified", property(lambda self: False))
    monkeypatch.setattr(address_type, "is_multicast", property(lambda self: False))


@pytest.mark.parametrize(
    ("address", "address_type"),
    [
        ("192.0.0.8", ipaddress.IPv4Address),
        ("64:ff9b:1::1", ipaddress.IPv6Address),
        ("100:0:0:1::1", ipaddress.IPv6Address),
        ("2001:2::1", ipaddress.IPv6Address),
        ("2002::1", ipaddress.IPv6Address),
        ("3fff::1", ipaddress.IPv6Address),
        ("5f00::1", ipaddress.IPv6Address),
    ],
)
def test_reviewed_non_global_compatibility_ranges_remain_denied_when_stdlib_says_global(
    monkeypatch: pytest.MonkeyPatch,
    address: str,
    address_type: type[ipaddress.IPv4Address | ipaddress.IPv6Address],
) -> None:
    """Deny reviewed compatibility ranges independently of stdlib patch data."""
    _force_address_properties(
        monkeypatch,
        address_type,
        private=False,
        global_=True,
    )

    with pytest.raises(EgressNotAllowedError, match="egress URL is not allowed"):
        _validate_global_address(address, _REMOTE_POLICY, hostname="api.example.com")


@pytest.mark.parametrize(
    ("address", "address_type"),
    [
        ("192.0.0.9", ipaddress.IPv4Address),
        ("192.0.0.10", ipaddress.IPv4Address),
        ("2001:1::1", ipaddress.IPv6Address),
        ("2001:1::2", ipaddress.IPv6Address),
        ("2001:1::3", ipaddress.IPv6Address),
        ("2001:3::1", ipaddress.IPv6Address),
        ("2001:4:112::1", ipaddress.IPv6Address),
        ("2001:20::1", ipaddress.IPv6Address),
        ("2001:30::1", ipaddress.IPv6Address),
    ],
)
def test_current_iana_global_exceptions_remain_allowed_when_stdlib_parent_is_private(
    monkeypatch: pytest.MonkeyPatch,
    address: str,
    address_type: type[ipaddress.IPv4Address | ipaddress.IPv6Address],
) -> None:
    """Honor explicit IANA-global exceptions despite stale parent classification."""
    _force_address_properties(
        monkeypatch,
        address_type,
        private=True,
        global_=False,
    )

    assert (
        _validate_global_address(address, _REMOTE_POLICY, hostname="api.example.com")
        == address
    )


@pytest.mark.parametrize("address", ["192.0.0.9", "2001:1::1"])
@pytest.mark.parametrize(
    ("hostname", "policy"),
    [
        ("localhost", EgressPolicy.from_hosts([], allow_local=True)),
        ("ollama", EgressPolicy.from_hosts("ollama", allow_local=True)),
    ],
)
def test_global_compatibility_exceptions_do_not_widen_local_hostname_authority(
    address: str,
    hostname: str,
    policy: EgressPolicy,
) -> None:
    """Keep local-development address scope narrower than remote compatibility."""
    with pytest.raises(EgressNotAllowedError, match="egress URL is not allowed"):
        _validate_global_address(address, policy, hostname=hostname)
