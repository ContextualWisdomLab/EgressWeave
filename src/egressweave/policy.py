"""Egress policy — the single injected dependency for egressweave.

The policy decouples the SSRF / DNS-rebinding guard from any one
application's settings object. It carries the allowlist of hostnames that
outbound requests may target, plus an ``allow_local`` escape hatch for local
development stacks (loopback and Docker-container names that resolve to
RFC 1918 addresses).

Construct it explicitly::

    policy = EgressPolicy.from_hosts("api.openai.com, api.anthropic.com")

or, for a local Ollama-style stack::

    policy = EgressPolicy.from_hosts("ollama", allow_local=True)
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

DEFAULT_DNS_RESOLUTION_TIMEOUT_SECONDS = 5.0


def _normalize_host(value: str) -> str:
    """Return the canonical comparison form for a hostname."""
    return value.strip().lower().rstrip(".")


@dataclass(frozen=True)
class EgressPolicy:
    """Immutable outbound-egress allowlist policy.

    ``allowed_hosts`` is the exhaustive set of hostnames an outbound request
    may target. Values are normalized (lower-cased, trailing dot stripped) on
    construction so equality checks are exact. ``allow_local`` widens the guard
    to accept loopback addresses and single-label allowlisted hosts (Docker
    container names) that resolve to private addresses — intended for local
    development only.
    """

    allowed_hosts: frozenset[str]
    allow_local: bool = False
    dns_timeout_seconds: float = DEFAULT_DNS_RESOLUTION_TIMEOUT_SECONDS

    def __post_init__(self) -> None:
        normalized = frozenset(
            _normalize_host(host) for host in self.allowed_hosts if host and host.strip()
        )
        # Frozen dataclass: bypass the immutability guard exactly once to store
        # the normalized set built from caller input.
        object.__setattr__(self, "allowed_hosts", normalized)

    @classmethod
    def from_hosts(
        cls,
        hosts: str | Iterable[str],
        *,
        allow_local: bool = False,
        dns_timeout_seconds: float = DEFAULT_DNS_RESOLUTION_TIMEOUT_SECONDS,
    ) -> "EgressPolicy":
        """Build a policy from a comma-separated string or an iterable of hosts."""
        items: Iterable[str]
        if isinstance(hosts, str):
            items = hosts.split(",")
        else:
            items = hosts
        return cls(
            allowed_hosts=frozenset(items),
            allow_local=allow_local,
            dns_timeout_seconds=dns_timeout_seconds,
        )

    def is_allowlisted_local_host(self, hostname: str) -> bool:
        """Whether ``hostname`` is an allowlisted single-label local host.

        Matches the Docker-container-name case: ``allow_local`` is enabled, the
        host is in the allowlist, and it is a bare single label (no dots, not an
        IP literal) — e.g. ``ollama``. Callers still resolve and re-check the
        address; this only governs the local escape hatch.
        """
        normalized = _normalize_host(hostname)
        return (
            self.allow_local
            and normalized in self.allowed_hosts
            and "." not in normalized
        )
