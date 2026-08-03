"""Egress policy — the single injected dependency for egressweave.

The policy decouples the SSRF / DNS-rebinding guard from any one
application's settings object. It carries exact hostname and TCP-port
allowlists, plus an ``allow_local`` escape hatch for local development stacks:
built-in local names are bound to loopback, while explicit Docker-container
names may resolve to RFC 1918 or RFC 4193 addresses.

Construct it explicitly::

    policy = EgressPolicy.from_hosts("api.openai.com, api.anthropic.com")

or, for a local Ollama-style stack::

    policy = EgressPolicy.from_hosts(
        "ollama", allow_local=True, allowed_ports=(11434,)
    )
"""

from __future__ import annotations

import math
from collections.abc import Iterable
from dataclasses import dataclass

DEFAULT_ALLOWED_PORTS = frozenset({80, 443})
DEFAULT_DNS_RESOLUTION_TIMEOUT_SECONDS = 5.0


def _normalize_host(value: str) -> str:
    """Return the canonical comparison form for a hostname."""
    return value.strip().lower().rstrip(".")


@dataclass(frozen=True)
class EgressPolicy:
    """Immutable outbound-egress allowlist policy.

    ``allowed_hosts`` is the exhaustive set of hostnames an outbound request
    may target. ``allowed_ports`` is the exhaustive set of TCP destination
    ports, defaulting to standard HTTP and HTTPS ports. Values are normalized
    on construction so comparisons are exact. ``allow_local`` widens the guard
    only for hostname-bound local development: built-in local names accept
    loopback, while single-label allowlisted container names accept loopback,
    RFC 1918 IPv4, or RFC 4193 IPv6 unique-local addresses.
    """

    allowed_hosts: frozenset[str]
    allowed_ports: frozenset[int] = DEFAULT_ALLOWED_PORTS
    allow_local: bool = False
    dns_timeout_seconds: float = DEFAULT_DNS_RESOLUTION_TIMEOUT_SECONDS

    def __post_init__(self) -> None:
        """Normalize policy values and reject unsafe ports or DNS timeouts."""
        normalized_hosts = frozenset(
            _normalize_host(host) for host in self.allowed_hosts if host and host.strip()
        )
        normalized_ports: set[int] = set()
        for port in self.allowed_ports:
            if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
                raise ValueError("allowed_ports must contain integers from 1 through 65535")
            normalized_ports.add(port)

        timeout = self.dns_timeout_seconds
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)):
            raise ValueError("dns_timeout_seconds must be a finite positive number")
        try:
            normalized_timeout = float(timeout)
        except (OverflowError, ValueError) as exc:
            raise ValueError(
                "dns_timeout_seconds must be a finite positive number"
            ) from exc
        if not math.isfinite(normalized_timeout) or normalized_timeout <= 0:
            raise ValueError("dns_timeout_seconds must be a finite positive number")
        # Frozen dataclass: bypass the immutability guard exactly once to store
        # the normalized values built from caller input.
        object.__setattr__(self, "allowed_hosts", normalized_hosts)
        object.__setattr__(self, "allowed_ports", frozenset(normalized_ports))
        object.__setattr__(self, "dns_timeout_seconds", normalized_timeout)

    @classmethod
    def from_hosts(
        cls,
        hosts: str | Iterable[str],
        *,
        allowed_ports: Iterable[int] = DEFAULT_ALLOWED_PORTS,
        allow_local: bool = False,
        dns_timeout_seconds: float = DEFAULT_DNS_RESOLUTION_TIMEOUT_SECONDS,
    ) -> EgressPolicy:
        """Build a policy from hosts plus an explicit TCP destination-port set."""
        items: Iterable[str]
        if isinstance(hosts, str):
            items = hosts.split(",")
        else:
            items = hosts
        return cls(
            allowed_hosts=frozenset(items),
            allowed_ports=frozenset(allowed_ports),
            allow_local=allow_local,
            dns_timeout_seconds=dns_timeout_seconds,
        )

    def is_port_allowed(self, port: int) -> bool:
        """Return whether ``port`` is an explicitly allowed TCP destination."""
        return port in self.allowed_ports

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
