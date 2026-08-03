"""Egress policy — the single injected dependency for egressweave.

The policy decouples the SSRF / DNS-rebinding guard from any one
application's settings object. It carries the allowlist of hostnames that
outbound requests may target, plus an ``allow_local`` escape hatch for local
development stacks: built-in local names are bound to loopback, while explicit
Docker-container names may resolve to RFC 1918 or RFC 4193 addresses.

Construct it explicitly::

    policy = EgressPolicy.from_hosts("api.openai.com, api.anthropic.com")

or, for a local Ollama-style stack::

    policy = EgressPolicy.from_hosts("ollama", allow_local=True)
"""

from __future__ import annotations

import ipaddress
import math
from collections.abc import Iterable
from dataclasses import dataclass
from numbers import Real

DEFAULT_DNS_RESOLUTION_TIMEOUT_SECONDS = 5.0
_INVALID_HOST_DELIMITERS = frozenset("*/\\@?:#%")


def _normalize_host(value: str) -> str:
    """Return the canonical comparison form for a hostname."""
    return value.strip().lower().rstrip(".")


def _looks_like_ip_literal(candidate: str) -> bool:
    """Return whether ``candidate`` uses a literal or legacy IP-like form."""
    try:
        ipaddress.ip_address(candidate)
    except ValueError:
        compact_candidate = candidate.replace(".", "").lower()
        return compact_candidate.isdigit() or compact_candidate.startswith("0x")
    return True


def _normalize_allowed_host(value: object) -> str | None:
    """Normalize one exact hostname or reject unusable policy configuration.

    Empty strings remain ignorable so comma-separated environment variables may
    contain harmless extra separators. Every non-empty entry must be a hostname,
    not a URL, wildcard, credential-bearing authority, port-qualified authority,
    IP literal, or legacy numeric IP representation. Those forms can never pass
    runtime URL validation, so accepting them here would defer a deterministic
    configuration error until the first request.
    """
    if not isinstance(value, str):
        raise ValueError("allowed_hosts entries must be exact hostname strings")

    normalized = _normalize_host(value)
    if not normalized:
        return None

    if (
        any(
            character.isspace() or ord(character) < 32 or ord(character) == 127
            for character in normalized
        )
        or any(delimiter in normalized for delimiter in _INVALID_HOST_DELIMITERS)
        or _looks_like_ip_literal(normalized)
    ):
        raise ValueError(
            "allowed_hosts entries must be exact hostnames without wildcards, URL syntax, "
            "or IP literals"
        )
    return normalized


@dataclass(frozen=True)
class EgressPolicy:
    """Immutable outbound-egress allowlist policy.

    ``allowed_hosts`` is the exhaustive set of hostnames an outbound request
    may target. Values are normalized (lower-cased, trailing dot stripped) on
    construction so equality checks are exact. Invalid entries that can never
    be authorized—such as wildcards, URLs, ports, credentials, or IP literals—
    fail fast during policy construction rather than on the first request.
    ``allow_local`` widens the guard only for hostname-bound local development:
    built-in local names accept loopback, while single-label allowlisted
    container names accept loopback, RFC 1918 IPv4, or RFC 4193 IPv6
    unique-local addresses.

    ``dns_timeout_seconds`` is a finite positive deadline applied to both
    synchronous and asynchronous DNS resolution. Invalid timeout values are
    rejected during construction so callers cannot accidentally disable the
    fail-closed resolution budget.
    """

    allowed_hosts: frozenset[str]
    allow_local: bool = False
    dns_timeout_seconds: float = DEFAULT_DNS_RESOLUTION_TIMEOUT_SECONDS

    def __post_init__(self) -> None:
        timeout = self.dns_timeout_seconds
        if (
            isinstance(timeout, bool)
            or not isinstance(timeout, Real)
            or not math.isfinite(timeout)
            or timeout <= 0
        ):
            raise ValueError("dns_timeout_seconds must be a finite positive number")

        normalized_hosts: set[str] = set()
        for host in self.allowed_hosts:
            normalized_host = _normalize_allowed_host(host)
            if normalized_host is not None:
                normalized_hosts.add(normalized_host)

        # Frozen dataclass: bypass the immutability guard exactly once to store
        # normalized caller input and a canonical float timeout.
        object.__setattr__(self, "allowed_hosts", frozenset(normalized_hosts))
        object.__setattr__(self, "dns_timeout_seconds", float(timeout))

    @classmethod
    def from_hosts(
        cls,
        hosts: str | Iterable[str],
        *,
        allow_local: bool = False,
        dns_timeout_seconds: float = DEFAULT_DNS_RESOLUTION_TIMEOUT_SECONDS,
    ) -> EgressPolicy:
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
        return self.allow_local and normalized in self.allowed_hosts and "." not in normalized
