"""Regression tests for exact host-and-port authority policy semantics."""

import pytest

from egressweave import EgressNotAllowedError, EgressPolicy, validate_egress_url_details
from egressweave import validation as v


def test_from_authorities_preserves_only_explicit_host_port_pairs() -> None:
    """Do not manufacture a host-by-port Cartesian product from policy input."""
    policy = EgressPolicy.from_authorities(
        [
            ("api.example.com", 443),
            ("admin.example.com", "8443"),
        ]
    )

    assert policy.allowed_hosts == frozenset(
        {"api.example.com", "admin.example.com"}
    )
    assert policy.allowed_ports == frozenset({443, 8443})
    assert policy.allowed_authorities == frozenset(
        {("api.example.com", 443), ("admin.example.com", 8443)}
    )
    assert policy.allows_authority("api.example.com", 443) is True
    assert policy.allows_authority("admin.example.com", 8443) is True
    assert policy.allows_authority("api.example.com", 8443) is False
    assert policy.allows_authority("admin.example.com", 443) is False


def test_from_hosts_rejects_an_ambiguous_many_by_many_policy() -> None:
    """Require exact pairs when several hosts and several ports are supplied."""
    with pytest.raises(ValueError, match="exact authority pairs"):
        EgressPolicy.from_hosts(
            "api.example.com, admin.example.com",
            allowed_ports={443, 8443},
        )


def test_from_hosts_derives_pairs_when_only_one_policy_axis_varies() -> None:
    """Preserve concise configuration for one-port or one-host integrations."""
    shared_tls_port = EgressPolicy.from_hosts(
        "api.example.com, admin.example.com"
    )
    one_host_many_ports = EgressPolicy.from_hosts(
        "api.example.com", allowed_ports={443, 8443}
    )

    assert shared_tls_port.allowed_authorities == frozenset(
        {("api.example.com", 443), ("admin.example.com", 443)}
    )
    assert one_host_many_ports.allowed_authorities == frozenset(
        {("api.example.com", 443), ("api.example.com", 8443)}
    )


def test_authority_pairs_normalize_host_identity_and_decimal_ports() -> None:
    """Use the same IDNA and port canonicalization as existing policy inputs."""
    policy = EgressPolicy.from_authorities(
        [
            ("BÜCHER.example.", "443"),
            ("xn--bcher-kva.example", 443),
        ]
    )

    assert policy.allowed_authorities == frozenset(
        {("xn--bcher-kva.example", 443)}
    )
    assert policy.allows_authority("bücher.example", 443) is True


@pytest.mark.parametrize(
    "invalid_authority",
    [
        "api.example.com:443",
        ("api.example.com",),
        ("api.example.com", 443, "GET"),
        ("", 443),
        ("api.example.com", 0),
    ],
)
def test_invalid_authority_pair_configuration_fails_fast(invalid_authority) -> None:
    """Reject malformed pair shapes, hosts, and ports during construction."""
    with pytest.raises((TypeError, ValueError), match="authorit|allowed_ports|exact hostnames"):
        EgressPolicy.from_authorities([invalid_authority])


def test_direct_authority_configuration_must_match_its_projections() -> None:
    """Prevent contradictory direct dataclass configuration from becoming policy."""
    with pytest.raises(ValueError, match="match allowed_hosts and allowed_ports"):
        EgressPolicy(
            allowed_hosts=frozenset({"api.example.com", "admin.example.com"}),
            allowed_ports=frozenset({443, 8443}),
            allowed_authorities=frozenset({("api.example.com", 443)}),
        )


def test_unlisted_host_port_pair_is_rejected_before_dns_resolution(monkeypatch) -> None:
    """Deny a cross-pair authority without allowing resolver side effects."""
    policy = EgressPolicy.from_authorities(
        [
            ("api.example.com", 443),
            ("admin.example.com", 8443),
        ]
    )

    def unexpected_dns(*args, **kwargs):  # pragma: no cover - failure sentinel
        raise AssertionError("authority rejection must happen before DNS resolution")

    monkeypatch.setattr(v.socket, "getaddrinfo", unexpected_dns)

    with pytest.raises(EgressNotAllowedError, match="^egress URL is not allowed$"):
        validate_egress_url_details(
            "https://api.example.com:8443/v1", policy=policy
        )


def test_listed_host_port_pair_reaches_dns_resolution(monkeypatch) -> None:
    """Resolve an explicitly authorized pair and preserve the normalized URL."""
    policy = EgressPolicy.from_authorities(
        [
            ("api.example.com", 443),
            ("admin.example.com", 8443),
        ]
    )

    def fake_getaddrinfo(host, port, type=None):
        assert host == "admin.example.com"
        assert port == 8443
        return [(2, 1, 6, "", ("93.184.216.34", port))]

    monkeypatch.setattr(v.socket, "getaddrinfo", fake_getaddrinfo)

    details = validate_egress_url_details(
        "https://ADMIN.Example.com:08443/v1", policy=policy
    )

    assert details is not None
    assert details.normalized_url == "https://admin.example.com:8443/v1"
    assert details.hostname == "admin.example.com"
    assert details.port == 8443
