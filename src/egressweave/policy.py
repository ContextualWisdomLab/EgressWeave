"""Egress policy — the single injected dependency for egressweave.

The policy decouples the SSRF / DNS-rebinding guard from any one
application's settings object. It carries the allowlists of hostnames, network
ports, and HTTP methods that outbound requests may target, plus an
``allow_local`` escape hatch for local development stacks: built-in local names
are bound to loopback, while explicit Docker-container names may resolve to RFC
1918 or RFC 4193 addresses.

Construct it explicitly::

    policy = EgressPolicy.from_hosts("api.openai.com, api.anthropic.com")

or, for a read-only integration on an explicit alternate TLS port::

    policy = EgressPolicy.from_hosts(
        "api.example.com",
        allowed_ports={443, 8443},
        allowed_methods={"GET", "HEAD"},
    )
"""

from __future__ import annotations

import ipaddress
import math
from collections.abc import Iterable
from dataclasses import dataclass
from numbers import Real

DEFAULT_DNS_RESOLUTION_TIMEOUT_SECONDS = 5.0
DEFAULT_ALLOWED_EGRESS_PORTS = frozenset({443})
DEFAULT_ALLOWED_HTTP_METHODS = frozenset(
    {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}
)
_INVALID_HOST_DELIMITERS = frozenset("*/\\@?:#%")
_HTTP_METHOD_TOKEN_CHARACTERS = frozenset(
    "!#$%&'*+-.^_`|~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
)


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
        raise TypeError("allowed_hosts entries must be exact hostname strings")

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


def _normalize_allowed_port(value: object) -> int | None:
    """Normalize one positive TCP port or reject unsafe configuration.

    Decimal strings are accepted for environment-variable ergonomics. Empty
    string segments remain ignorable, while booleans, non-decimal values, port
    zero, and values outside the TCP/UDP port range fail at construction.
    """
    if isinstance(value, str):
        normalized = value.strip()
        if not normalized:
            return None
        if not normalized.isascii() or not normalized.isdigit():
            raise ValueError("allowed_ports entries must be decimal port numbers")
        port = int(normalized)
    else:
        if isinstance(value, bool) or not isinstance(value, int):
            raise TypeError("allowed_ports entries must be integer port numbers")
        port = value

    if not 1 <= port <= 65535:
        raise ValueError("allowed_ports entries must be between 1 and 65535")
    return port


def _normalize_allowed_method(value: object) -> str:
    """Return one canonical HTTP method token or reject unsafe configuration.

    Method names follow the RFC 9110 ``token`` grammar and are normalized to
    uppercase because HTTPX serializes method names in uppercase. ``CONNECT``
    is never accepted: its semantics create an application-layer tunnel whose
    destination is independent of the validated URL authority.
    """
    if not isinstance(value, str):
        raise TypeError("allowed_methods entries must be HTTP method strings")

    normalized = value.strip().upper()
    if (
        not normalized
        or any(character not in _HTTP_METHOD_TOKEN_CHARACTERS for character in normalized)
    ):
        raise ValueError("allowed_methods entries must be valid HTTP method tokens")
    if normalized == "CONNECT":
        raise ValueError("CONNECT cannot be authorized by an egress policy")
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
    unique-local addresses. It must be an actual boolean; truthy strings or
    integers are rejected so configuration parsing cannot accidentally enable
    the local-network escape hatch.

    ``allowed_ports`` is the exhaustive set of destination TCP ports. The
    secure default authorizes only the standard HTTPS port, 443. Alternate TLS
    ports and local-development HTTP ports require explicit opt-in because RFC
    9110 defines scheme, host, and port together as the request origin.

    ``dns_timeout_seconds`` is a finite positive deadline applied to both
    synchronous and asynchronous DNS resolution. Invalid timeout values are
    rejected during construction so callers cannot accidentally disable the
    fail-closed resolution budget.

    ``allowed_methods`` is the exhaustive set of HTTP methods that pinned
    clients may dispatch. The secure default covers ordinary API operations but
    excludes TRACE, WebDAV extension methods, and every other unrequested method.
    ``CONNECT`` is always invalid because it can ask an allowlisted proxy to open
    a tunnel to a second, unvalidated destination.
    """

    allowed_hosts: frozenset[str]
    allow_local: bool = False
    dns_timeout_seconds: float = DEFAULT_DNS_RESOLUTION_TIMEOUT_SECONDS
    allowed_ports: frozenset[int] = DEFAULT_ALLOWED_EGRESS_PORTS
    allowed_methods: frozenset[str] = DEFAULT_ALLOWED_HTTP_METHODS

    def __post_init__(self) -> None:
        if not isinstance(self.allow_local, bool):
            raise TypeError("allow_local must be a boolean")

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

        port_values: Iterable[object]
        if isinstance(self.allowed_ports, str):
            port_values = self.allowed_ports.split(",")
        else:
            port_values = self.allowed_ports
        normalized_ports: set[int] = set()
        for port in port_values:
            normalized_port = _normalize_allowed_port(port)
            if normalized_port is not None:
                normalized_ports.add(normalized_port)

        method_values: Iterable[object]
        if isinstance(self.allowed_methods, str):
            method_values = self.allowed_methods.split(",")
        else:
            method_values = self.allowed_methods
        normalized_methods = frozenset(
            _normalize_allowed_method(method) for method in method_values
        )

        # Frozen dataclass: bypass the immutability guard exactly once to store
        # normalized caller input and a canonical float timeout.
        object.__setattr__(self, "allowed_hosts", frozenset(normalized_hosts))
        object.__setattr__(self, "dns_timeout_seconds", float(timeout))
        object.__setattr__(self, "allowed_ports", frozenset(normalized_ports))
        object.__setattr__(self, "allowed_methods", normalized_methods)

    @classmethod
    def from_hosts(
        cls,
        hosts: str | Iterable[str],
        *,
        allow_local: bool = False,
        dns_timeout_seconds: float = DEFAULT_DNS_RESOLUTION_TIMEOUT_SECONDS,
        allowed_ports: str | Iterable[int | str] = DEFAULT_ALLOWED_EGRESS_PORTS,
        allowed_methods: str | Iterable[str] = DEFAULT_ALLOWED_HTTP_METHODS,
    ) -> EgressPolicy:
        """Build a policy from host, port, and HTTP-method strings or iterables."""
        items: Iterable[str]
        if isinstance(hosts, str):
            items = hosts.split(",")
        else:
            items = hosts

        port_items: Iterable[int | str]
        if isinstance(allowed_ports, str):
            port_items = allowed_ports.split(",")
        else:
            port_items = allowed_ports

        method_items: Iterable[str]
        if isinstance(allowed_methods, str):
            method_items = allowed_methods.split(",")
        else:
            method_items = allowed_methods

        return cls(
            allowed_hosts=frozenset(items),
            allow_local=allow_local,
            dns_timeout_seconds=dns_timeout_seconds,
            allowed_ports=frozenset(port_items),
            allowed_methods=frozenset(method_items),
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

    def allows_port(self, port: int) -> bool:
        """Return whether the effective destination port is authorized."""
        return (
            isinstance(port, int)
            and not isinstance(port, bool)
            and port in self.allowed_ports
        )

    def allows_http_method(self, method: str) -> bool:
        """Return whether ``method`` is authorized by this policy."""
        try:
            normalized = _normalize_allowed_method(method)
        except (TypeError, ValueError):
            return False
        return normalized in self.allowed_methods
