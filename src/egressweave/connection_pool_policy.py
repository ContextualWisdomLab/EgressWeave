"""Provider-neutral finite connection-pool limits for outbound HTTP.

The pinned transports use HTTPCore internally, but callers should not need to
import HTTPX private defaults or construct provider-specific limit objects.
This module stores the reviewed total-connection, idle-connection, and idle-age
bounds that both synchronous and asynchronous pools receive.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from numbers import Real


def _normalize_connection_count(
    field_name: str,
    value: object,
    *,
    allow_zero: bool,
) -> int:
    """Return one exact ASCII-compatible connection-count limit."""
    if isinstance(value, bool):
        raise TypeError(f"{field_name} must be an integer or ASCII decimal string")
    if type(value) is int:
        normalized = value
    elif type(value) is str:
        if not value or not value.isascii() or not value.isdecimal():
            raise ValueError(f"{field_name} must be an ASCII decimal string")
        normalized = int(value, 10)
    else:
        raise TypeError(f"{field_name} must be an integer or ASCII decimal string")

    minimum = 0 if allow_zero else 1
    if normalized < minimum:
        qualifier = "zero or greater" if allow_zero else "greater than zero"
        raise ValueError(f"{field_name} must be {qualifier}")
    return normalized


def _normalize_keepalive_expiry_seconds(value: object) -> float:
    """Return one finite non-negative idle-connection lifetime in seconds."""
    field_name = "keepalive_expiry_seconds"
    if isinstance(value, bool) or not isinstance(value, Real):
        raise TypeError(f"{field_name} must be a real number of seconds")
    normalized = float(value)
    if not math.isfinite(normalized) or normalized < 0:
        raise ValueError(f"{field_name} must be finite and zero or greater")
    return normalized


@dataclass(frozen=True, slots=True)
class EgressConnectionPoolPolicy:
    """Define immutable finite capacity for each pinned connection pool.

    ``max_connections`` is the maximum number of concurrent TCP connections the
    pool may own. ``max_keepalive_connections`` limits the subset retained while
    idle and may be zero to disable idle retention. Both count fields accept
    exact integers or exact ASCII decimal strings for environment-derived
    settings. ``keepalive_expiry_seconds`` limits how long an idle connection
    remains reusable and may be zero for immediate expiry. The defaults preserve
    HTTPX's documented finite baseline without importing HTTPX's private
    ``DEFAULT_LIMITS`` object.
    """

    max_connections: int | str = 100
    max_keepalive_connections: int | str = 20
    keepalive_expiry_seconds: float = 5.0

    def __post_init__(self) -> None:
        """Normalize every limit and reject contradictory pool capacity."""
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
        if max_keepalive_connections > max_connections:
            raise ValueError(
                "max_keepalive_connections must not exceed max_connections"
            )
        keepalive_expiry_seconds = _normalize_keepalive_expiry_seconds(
            self.keepalive_expiry_seconds
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

    def as_dict(self) -> dict[str, int | float]:
        """Return a detached provider-neutral representation of the limits."""
        return {
            "max_connections": self.max_connections,
            "max_keepalive_connections": self.max_keepalive_connections,
            "keepalive_expiry_seconds": self.keepalive_expiry_seconds,
        }


DEFAULT_EGRESS_CONNECTION_POOL_POLICY = EgressConnectionPoolPolicy()

__all__ = ["EgressConnectionPoolPolicy"]
