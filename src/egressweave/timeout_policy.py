"""Immutable phase-timeout ceilings for outbound HTTP requests.

HTTPX and HTTPCore represent request timeouts as four independent phase values:
connection establishment, response reads, request writes, and connection-pool
acquisition. This module stores the largest finite value that an EgressWeave
transport may delegate for each phase.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from numbers import Real


def _normalize_timeout_seconds(field_name: str, value: object) -> float:
    """Return one positive finite timeout maximum in seconds."""
    if isinstance(value, bool) or not isinstance(value, Real):
        raise TypeError(f"{field_name} must be a real number of seconds")
    normalized = float(value)
    if not math.isfinite(normalized) or normalized <= 0:
        raise ValueError(f"{field_name} must be finite and greater than zero")
    return normalized


@dataclass(frozen=True, slots=True)
class EgressTimeoutPolicy:
    """Define immutable ceilings for every HTTPCore request-timeout phase.

    Each value is the largest number of seconds a caller may delegate for that
    phase. Missing or explicitly disabled request values are replaced with the
    ceiling, larger values are capped, and stricter non-negative values are
    preserved. The defaults match HTTPX's ordinary five-second inactivity
    timeout while making the bound an explicit egress policy.
    """

    connect_timeout_seconds: float = 5.0
    read_timeout_seconds: float = 5.0
    write_timeout_seconds: float = 5.0
    pool_timeout_seconds: float = 5.0

    def __post_init__(self) -> None:
        """Normalize every configured maximum and reject unbounded values."""
        for field_name in (
            "connect_timeout_seconds",
            "read_timeout_seconds",
            "write_timeout_seconds",
            "pool_timeout_seconds",
        ):
            object.__setattr__(
                self,
                field_name,
                _normalize_timeout_seconds(field_name, getattr(self, field_name)),
            )

    def as_httpcore_timeout(self) -> dict[str, float]:
        """Return detached HTTPCore timeout-extension maxima."""
        return {
            "connect": self.connect_timeout_seconds,
            "read": self.read_timeout_seconds,
            "write": self.write_timeout_seconds,
            "pool": self.pool_timeout_seconds,
        }


DEFAULT_EGRESS_TIMEOUT_POLICY = EgressTimeoutPolicy()

__all__ = ["EgressTimeoutPolicy"]
