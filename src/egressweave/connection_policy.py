"""Immutable connection-pool allocation limits for outbound HTTP clients.

HTTPX and HTTPCore pool reusable TCP connections. This module makes the maximum
simultaneous connection count, idle keep-alive capacity, and idle retention
window explicit finite egress policy instead of inheriting mutable or unbounded
caller configuration.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from numbers import Real

DEFAULT_MAX_CONNECTIONS = 100
DEFAULT_MAX_KEEPALIVE_CONNECTIONS = 20
DEFAULT_KEEPALIVE_EXPIRY_SECONDS = 5.0


def _normalize_connection_count(
    field_name: str,
    value: object,
    *,
    allow_zero: bool,
) -> int:
    """Return one exact finite connection count with no permissive coercion."""
    if isinstance(value, str):
        normalized = value.strip()
        if not normalized or not normalized.isascii() or not normalized.isdigit():
            raise ValueError(f"{field_name} must be an ASCII decimal count")
        count = int(normalized)
    else:
        if isinstance(value, bool) or not isinstance(value, int):
            raise TypeError(f"{field_name} must be an integer count")
        count = value

    if count < 0 or (count == 0 and not allow_zero):
        requirement = "zero or greater" if allow_zero else "greater than zero"
        raise ValueError(f"{field_name} must be {requirement}")
    return count


def _normalize_keepalive_expiry_seconds(value: object) -> float:
    """Return one finite non-negative idle keep-alive lifetime in seconds."""
    if isinstance(value, bool) or not isinstance(value, Real):
        raise TypeError("keepalive_expiry_seconds must be a real number of seconds")
    normalized = float(value)
    if not math.isfinite(normalized) or normalized < 0:
        raise ValueError(
            "keepalive_expiry_seconds must be finite and zero or greater"
        )
    return normalized


@dataclass(frozen=True, slots=True)
class EgressConnectionPolicy:
    """Define immutable finite limits for one pinned HTTPCore connection pool.

    ``max_connections`` bounds simultaneous open or in-progress connections.
    ``max_keepalive_connections`` bounds the reusable idle subset and may be zero
    when an integration must not retain idle sockets. ``keepalive_expiry_seconds``
    bounds idle retention and may also be zero. The defaults preserve HTTPX's
    ordinary 100 total, 20 idle, and five-second limits while making them
    explicit, auditable, and integration-specific.
    """

    max_connections: int | str = DEFAULT_MAX_CONNECTIONS
    max_keepalive_connections: int | str = DEFAULT_MAX_KEEPALIVE_CONNECTIONS
    keepalive_expiry_seconds: float = DEFAULT_KEEPALIVE_EXPIRY_SECONDS

    def __post_init__(self) -> None:
        """Normalize every pool limit and reject contradictory configuration."""
        max_connections = _normalize_connection_count(
            "max_connections",
            self.max_connections,
            allow_zero=False,
        )
        max_keepalive_connections = _normalize_connection_count(
            "max_keepalive_connections",
            self.max_keepalive_connections,
            allow_zero=True,
        )
        keepalive_expiry_seconds = _normalize_keepalive_expiry_seconds(
            self.keepalive_expiry_seconds
        )
        if max_keepalive_connections > max_connections:
            raise ValueError(
                "max_keepalive_connections must not exceed max_connections"
            )

        object.__setattr__(self, "max_connections", max_connections)
        object.__setattr__(
            self,
            "max_keepalive_connections",
            max_keepalive_connections,
        )
        object.__setattr__(
            self,
            "keepalive_expiry_seconds",
            keepalive_expiry_seconds,
        )

    def as_httpcore_limits(self) -> dict[str, int | float]:
        """Return detached keyword values for an HTTPCore connection pool."""
        return {
            "max_connections": self.max_connections,
            "max_keepalive_connections": self.max_keepalive_connections,
            "keepalive_expiry": self.keepalive_expiry_seconds,
        }


DEFAULT_EGRESS_CONNECTION_POLICY = EgressConnectionPolicy()

__all__ = ["EgressConnectionPolicy"]
