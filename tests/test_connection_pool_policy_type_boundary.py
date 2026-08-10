"""Regression contracts for the exact connection-pool policy type boundary."""

from __future__ import annotations

import pytest

from egressweave import EgressConnectionPoolPolicy, EgressPolicy


class _HostileConnectionPoolPolicy(EgressConnectionPoolPolicy):
    """Model a subclass that changes a reviewed pool limit after construction."""

    def __init__(self) -> None:
        """Build valid base state before arming hostile attribute dispatch."""
        super().__init__()
        object.__setattr__(self, "_armed", True)

    def __getattribute__(self, name: str) -> object:
        """Replace the retained connection ceiling after base normalization."""
        if name == "max_connections":
            try:
                armed = object.__getattribute__(self, "_armed")
            except AttributeError:
                armed = False
            if armed:
                return 1_000_000_000
        return super().__getattribute__(name)


def _hostile_pool_policy() -> EgressConnectionPoolPolicy:
    """Return one valid subclass whose later pool ceiling is dynamically replaced."""
    policy = _HostileConnectionPoolPolicy()
    assert policy.max_connections == 1_000_000_000
    return policy


def test_host_policy_rejects_connection_pool_policy_subclass() -> None:
    """Reject non-exact pool policy types at trusted policy construction."""
    with pytest.raises(TypeError, match="connection_pool_policy"):
        EgressPolicy.from_hosts(
            "api.example.com",
            connection_pool_policy=_hostile_pool_policy(),
        )


def test_exact_authority_policy_rejects_connection_pool_policy_subclass() -> None:
    """Apply the same exact-type boundary to the authority-pair constructor."""
    with pytest.raises(TypeError, match="connection_pool_policy"):
        EgressPolicy.from_authorities(
            [("api.example.com", 443)],
            connection_pool_policy=_hostile_pool_policy(),
        )
