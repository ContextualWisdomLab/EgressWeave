"""Regression tests for the deliberately narrow ``allow_local`` escape hatch."""

import pytest

from egressweave import EgressNotAllowedError, EgressPolicy
from egressweave import validation as v


@pytest.mark.parametrize(
    "address",
    [
        "169.254.169.254",  # IPv4 link-local / common cloud metadata endpoint
        "fe80::1",  # IPv6 link-local
        "100.64.0.1",  # shared address space (CGNAT), not private
        "192.0.2.1",  # documentation range
        "198.18.0.1",  # benchmarking range
        "2001:db8::1",  # IPv6 documentation range
        "0.0.0.0",  # unspecified
        "224.0.0.1",  # multicast
        "240.0.0.1",  # reserved
    ],
)
def test_allowlisted_local_host_rejects_addresses_outside_private_or_loopback_ranges(
    address: str,
) -> None:
    policy = EgressPolicy.from_hosts("ollama", allow_local=True)

    with pytest.raises(EgressNotAllowedError):
        v._validate_global_address(address, policy, hostname="ollama")


def test_allow_local_does_not_allow_remote_host_to_rebind_to_loopback() -> None:
    policy = EgressPolicy.from_hosts("api.openai.com", allow_local=True)

    with pytest.raises(EgressNotAllowedError):
        v._validate_global_address(
            "127.0.0.1", policy, hostname="api.openai.com"
        )


def test_allowlisted_local_host_rejects_global_address() -> None:
    policy = EgressPolicy.from_hosts("ollama", allow_local=True)

    with pytest.raises(EgressNotAllowedError):
        v._validate_global_address(
            "93.184.216.34", policy, hostname="ollama"
        )


def test_localhost_rejects_non_loopback_address() -> None:
    policy = EgressPolicy.from_hosts([], allow_local=True)

    with pytest.raises(EgressNotAllowedError):
        v._validate_global_address(
            "93.184.216.34", policy, hostname="localhost"
        )


@pytest.mark.parametrize(
    "address",
    ["10.0.0.1", "172.16.0.1", "192.168.0.1", "fd00::1"],
)
def test_allowlisted_local_host_accepts_explicit_private_networks(address: str) -> None:
    policy = EgressPolicy.from_hosts("ollama", allow_local=True)

    assert v._validate_global_address(address, policy, hostname="ollama") == address
