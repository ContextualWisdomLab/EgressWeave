"""Regression contracts for the exact request-timeout policy type boundary."""

from __future__ import annotations

import pytest

from egressweave import EgressPolicy, EgressTimeoutPolicy


class _HostileTimeoutPolicy(EgressTimeoutPolicy):
    """Model a subclass that can replace the reviewed timeout export method."""

    def as_httpcore_timeout(self) -> dict[str, float]:
        """Fail if a later transport dynamically dispatches this override."""
        raise AssertionError("subclass-controlled timeout export executed")


def test_host_policy_rejects_timeout_policy_subclass() -> None:
    """Reject non-exact timeout policy types at trusted policy construction."""
    with pytest.raises(TypeError, match="request_timeout_policy"):
        EgressPolicy.from_hosts(
            "api.example.com",
            request_timeout_policy=_HostileTimeoutPolicy(),
        )


def test_exact_authority_policy_rejects_timeout_policy_subclass() -> None:
    """Apply the same exact-type boundary to the authority-pair constructor."""
    with pytest.raises(TypeError, match="request_timeout_policy"):
        EgressPolicy.from_authorities(
            [("api.example.com", 443)],
            request_timeout_policy=_HostileTimeoutPolicy(),
        )
