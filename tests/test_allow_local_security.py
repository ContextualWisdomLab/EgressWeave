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
