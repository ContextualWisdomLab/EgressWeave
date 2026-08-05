"""Egress policy — the single injected dependency for egressweave.

The policy decouples the SSRF / DNS-rebinding guard from any one
application's settings object. It carries exact host-and-port authorities, the
HTTP methods those authorities may receive, finite request- and response-body
budgets, finite request-phase timeout ceilings, and an ``allow_local`` escape
hatch for local development stacks: built-in local names are bound to loopback,
while explicit Docker-container names may resolve to RFC 1918 or RFC 4193
addresses.

Construct a concise one-port policy explicitly::

    policy = EgressPolicy.from_hosts("api.openai.com, api.anthropic.com")

Use exact pairs whenever both the host and port axes vary::

    policy = EgressPolicy.from_authorities(
        [
            ("api.example.com", 443),
            ("admin.example.com", 8443),
        ],
        allowed_methods={"GET", "HEAD"},
        max_request_bytes=2 * 1024 * 1024,
        max_response_bytes=4 * 1024 * 1024,
    )
"""

from __future__ import annotations

import ipaddress
import math
from collections.abc import Iterable
from dataclasses import dataclass
from numbers import Real

import idna

from egressweave.timeout_policy import (
    DEFAULT_EGRESS_TIMEOUT_POLICY,
    EgressTimeoutPolicy,
)

DEFAULT_DNS_RESOLUTION_TIMEOUT_SECONDS = 5.0
DEFAULT_MAX_REQUEST_BYTES = 16 * 1024 * 1024
DEFAULT_MAX_RESPONSE_BYTES = 16 * 1024 * 1024
DEFAULT_ALLOWED_EGRESS_PORTS = frozenset({443})
DEFAULT_ALLOWED_HTTP_METHODS = frozenset(
    {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}
)
_INVALID_HOST_DELIMITERS = frozenset("*/\\@?:#%")
_ALLOWED_HOST_CONFIGURATION_ERROR = (
    "allowed_hosts entries must be exact hostnames without wildcards, URL syntax, "
    "invalid IDNA labels, or IP literals"
)
_HTTP_METHOD_TOKEN_CHARACTERS = frozenset(
    "!#$%&'*+-.^_`|~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
)


def _canonicalize_host(value: str) -> str:
    """Return one validated lowercase ASCII hostname comparison form.

    UTS #46 non-transitional processing maps user-facing Unicode hostnames to
    their IDNA2008-compatible A-label form. STD3 rules reject characters that
    are not valid in hostname labels, while the IDNA implementation also
    enforces per-label and total DNS length limits. A single trailing root dot
    is accepted and removed from the comparison form.
    """
    try:
        encoded = idna.encode(value.strip(), uts46=True, std3_rules=True)
    except (idna.IDNAError, UnicodeError) as exc:
        raise ValueError("hostname is not valid under IDNA") from exc
    return encoded.decode("ascii").lower().rstrip(".")


def _normalize_host(value: str) -> str:
    """Return the canonical comparison form for a hostname when possible.

    Runtime URL validation must preserve its generic rejection boundary. An
    invalid hostname therefore falls back to a simple textual normalization;
    it cannot match a policy entry because policy construction accepts only
    successfully canonicalized hostnames.
    """
    try:
        return _canonicalize_host(value)
    except ValueError:
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
    IP literal, legacy numeric IP representation, or malformed IDNA name. Valid
    Unicode names are converted to lowercase ASCII A-labels before comparison,
    DNS resolution, TLS SNI, and HTTP authority construction.
    """
    if not isinstance(value, str):
        raise TypeError("allowed_hosts entries must be exact hostname strings")

    stripped = value.strip()
    if not stripped:
        return None

    if (
        any(
            character.isspace() or ord(character) < 32 or ord(character) == 127
            for character in stripped
        )
        or any(delimiter in stripped for delimiter in _INVALID_HOST_DELIMITERS)
    ):
        raise ValueError(_ALLOWED_HOST_CONFIGURATION_ERROR)

    try:
        normalized = _canonicalize_host(stripped)
    except ValueError as exc:
        raise ValueError(_ALLOWED_HOST_CONFIGURATION_ERROR) from exc

    if _looks_like_ip_literal(normalized):
        raise ValueError(_ALLOWED_HOST_CONFIGURATION_ERROR)
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


def _normalize_allowed_authority(value: object) -> tuple[str, int]:
    """Normalize one exact ``(hostname, port)`` policy pair.

    Authority entries deliberately use a two-item tuple instead of parsing a
    colon-delimited string. This keeps hostname and port validation independent,
    avoids authority-parser ambiguity, and ensures Unicode hostnames and decimal
    environment ports pass through the same canonicalizers as ``from_hosts``.
    """
    if not isinstance(value, tuple) or len(value) != 2:
        raise TypeError(
            "allowed_authorities entries must be (hostname, port) tuples"
        )

    hostname = _normalize_allowed_host(value[0])
    if hostname is None:
        raise ValueError("allowed_authorities hostnames must not be empty")
    port = _normalize_allowed_port(value[1])
    if port is None:
        raise ValueError("allowed_authorities ports must not be empty")
    return hostname, port


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


def _normalize_positive_byte_count(value: object, field_name: str) -> int:
    """Return one positive byte budget with field-specific safe errors."""
    if isinstance(value, str):
        normalized = value.strip()
        if not normalized or not normalized.isascii() or not normalized.isdigit():
            raise ValueError(
                f"{field_name} must be a positive decimal byte count"
            )
        byte_count = int(normalized)
    else:
        if isinstance(value, bool) or not isinstance(value, int):
            raise TypeError(f"{field_name} must be an integer byte count")
        byte_count = value

    if byte_count <= 0:
        raise ValueError(f"{field_name} must be greater than zero")
    return byte_count


def _normalize_max_request_bytes(value: object) -> int:
    """Return one positive outbound request-body byte budget."""
    return _normalize_positive_byte_count(value, "max_request_bytes")


def _normalize_max_response_bytes(value: object) -> int:
    """Return one positive inbound response-body byte budget."""
    return _normalize_positive_byte_count(value, "max_response_bytes")


@dataclass(frozen=True)
class EgressPolicy:
    """Immutable outbound-egress allowlist and resource policy.

    ``allowed_authorities`` is the authoritative set of normalized hostname and
    TCP-port pairs an outbound request may target. ``allowed_hosts`` and
    ``allowed_ports`` remain exposed as projections for compatibility and
    operator inspection, but runtime authorization always checks the complete
    pair. ``from_hosts`` derives exact pairs when either only one host or only one
    port axis varies; supplying several hosts and several ports is rejected as
    ambiguous, because silently taking their Cartesian product can authorize an
    unintended service. Use :meth:`from_authorities` for that case.

    Hostnames are normalized to lowercase ASCII A-labels using UTS #46
    non-transitional IDNA processing and STD3 hostname rules. Invalid entries
    that can never be authorized—such as wildcards, URLs, malformed DNS labels,
    ports, credentials, or IP literals—fail fast during policy construction.
    ``allow_local`` widens the address class only for an already allowlisted
    local authority. It must be an actual boolean so truthy deployment strings
    cannot accidentally enable access to loopback or private networks.

    ``dns_timeout_seconds`` is a finite positive deadline applied to both
    synchronous and asynchronous DNS resolution. Invalid timeout values are
    rejected during construction so callers cannot accidentally disable the
    fail-closed resolution budget.

    ``allowed_methods`` is the exhaustive set of HTTP methods that pinned
    clients may dispatch. The secure default covers ordinary API operations but
    excludes TRACE, WebDAV extension methods, and every other unrequested method.
    ``CONNECT`` is always invalid because it can ask an allowlisted proxy to open
    a tunnel to a second, unvalidated destination.

    ``request_timeout_policy`` caps the connect, read, write, and pool timeout
    values delegated to HTTPCore. Missing or explicitly disabled request values
    receive the finite policy maximum, while stricter caller values are retained.

    ``max_request_bytes`` is the largest outbound request body a returned client
    will consume from its caller. The finite 16 MiB default rejects an oversized
    declared length before pool dispatch and also counts actual synchronous or
    asynchronous stream bytes, including chunked and under-declared content.

    ``max_response_bytes`` is the largest decoded response body a returned
    client will expose. The finite 16 MiB default protects ordinary JSON API
    integrations from an allowlisted but compromised or attacker-controlled
    authority returning an unbounded body. Operators can choose smaller or
    larger positive request and response budgets for a specific integration,
    but cannot disable either boundary with zero, a negative value, a boolean,
    or malformed text.
    """

    allowed_hosts: frozenset[str]
    allow_local: bool = False
    dns_timeout_seconds: float = DEFAULT_DNS_RESOLUTION_TIMEOUT_SECONDS
    allowed_ports: frozenset[int] = DEFAULT_ALLOWED_EGRESS_PORTS
    allowed_methods: frozenset[str] = DEFAULT_ALLOWED_HTTP_METHODS
    max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES
    allowed_authorities: frozenset[tuple[str, int]] | None = None
    max_request_bytes: int = DEFAULT_MAX_REQUEST_BYTES
    request_timeout_policy: EgressTimeoutPolicy = DEFAULT_EGRESS_TIMEOUT_POLICY

    def __post_init__(self) -> None:
        """Validate and canonicalize every immutable policy field."""
        if not isinstance(self.allow_local, bool):
            raise TypeError("allow_local must be a boolean")
        if not isinstance(self.request_timeout_policy, EgressTimeoutPolicy):
            raise TypeError(
                "request_timeout_policy must be an EgressTimeoutPolicy"
            )

        timeout = self.dns_timeout_seconds
        if (
            isinstance(timeout, bool)
            or not isinstance(timeout, Real)
            or not math.isfinite(timeout)
            or timeout <= 0
        ):
            raise ValueError("dns_timeout_seconds must be a finite positive number")

        host_values: Iterable[object]
        if isinstance(self.allowed_hosts, str):
            host_values = self.allowed_hosts.split(",")
        else:
            host_values = self.allowed_hosts
        normalized_hosts: set[str] = set()
        for host in host_values:
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

        if self.allowed_authorities is None:
            if len(normalized_hosts) > 1 and len(normalized_ports) > 1:
                raise ValueError(
                    "multiple hosts and ports require exact authority pairs via "
                    "EgressPolicy.from_authorities"
                )
            normalized_authorities = frozenset(
                (hostname, port)
                for hostname in normalized_hosts
                for port in normalized_ports
            )
        else:
            normalized_authorities = frozenset(
                _normalize_allowed_authority(authority)
                for authority in self.allowed_authorities
            )
            authority_hosts = frozenset(
                hostname for hostname, _ in normalized_authorities
            )
            authority_ports = frozenset(port for _, port in normalized_authorities)
            if (
                authority_hosts != frozenset(normalized_hosts)
                or authority_ports != frozenset(normalized_ports)
            ):
                raise ValueError(
                    "allowed_authorities must match allowed_hosts and allowed_ports "
                    "projections"
                )

        method_values: Iterable[object]
        if isinstance(self.allowed_methods, str):
            method_values = self.allowed_methods.split(",")
        else:
            method_values = self.allowed_methods
        normalized_methods = frozenset(
            _normalize_allowed_method(method) for method in method_values
        )
        normalized_max_request_bytes = _normalize_max_request_bytes(
            self.max_request_bytes
        )
        normalized_max_response_bytes = _normalize_max_response_bytes(
            self.max_response_bytes
        )

        # Frozen dataclass: bypass the immutability guard exactly once per field
        # to store normalized caller input and canonical scalar values.
        object.__setattr__(self, "allowed_hosts", frozenset(normalized_hosts))
        object.__setattr__(self, "dns_timeout_seconds", float(timeout))
        object.__setattr__(self, "allowed_ports", frozenset(normalized_ports))
        object.__setattr__(self, "allowed_methods", normalized_methods)
        object.__setattr__(self, "max_request_bytes", normalized_max_request_bytes)
        object.__setattr__(self, "max_response_bytes", normalized_max_response_bytes)
        object.__setattr__(self, "allowed_authorities", normalized_authorities)

    @classmethod
    def from_hosts(
        cls,
        hosts: str | Iterable[str],
        *,
        allow_local: bool = False,
        dns_timeout_seconds: float = DEFAULT_DNS_RESOLUTION_TIMEOUT_SECONDS,
        allowed_ports: str | Iterable[int | str] = DEFAULT_ALLOWED_EGRESS_PORTS,
        allowed_methods: str | Iterable[str] = DEFAULT_ALLOWED_HTTP_METHODS,
        request_timeout_policy: EgressTimeoutPolicy = DEFAULT_EGRESS_TIMEOUT_POLICY,
        max_request_bytes: int | str = DEFAULT_MAX_REQUEST_BYTES,
        max_response_bytes: int | str = DEFAULT_MAX_RESPONSE_BYTES,
    ) -> EgressPolicy:
        """Build an unambiguous policy from host and port projections.

        The concise constructor remains appropriate when all configured hosts
        share one port or one host intentionally exposes several ports. Several
        hosts plus several ports is rejected; use :meth:`from_authorities` to
        enumerate the exact permitted pairs instead of authorizing a Cartesian
        product accidentally.
        """
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
            request_timeout_policy=request_timeout_policy,
            max_request_bytes=max_request_bytes,
            max_response_bytes=max_response_bytes,
        )

    @classmethod
    def from_authorities(
        cls,
        authorities: Iterable[tuple[str, int | str]],
        *,
        allow_local: bool = False,
        dns_timeout_seconds: float = DEFAULT_DNS_RESOLUTION_TIMEOUT_SECONDS,
        allowed_methods: str | Iterable[str] = DEFAULT_ALLOWED_HTTP_METHODS,
        request_timeout_policy: EgressTimeoutPolicy = DEFAULT_EGRESS_TIMEOUT_POLICY,
        max_request_bytes: int | str = DEFAULT_MAX_REQUEST_BYTES,
        max_response_bytes: int | str = DEFAULT_MAX_RESPONSE_BYTES,
    ) -> EgressPolicy:
        """Build a policy from exact normalized ``(hostname, port)`` pairs.

        Duplicate pairs collapse after hostname IDNA and decimal-port
        normalization. The resulting host and port projections remain available
        through ``allowed_hosts`` and ``allowed_ports``, while runtime decisions
        use ``allowed_authorities`` exclusively.
        """
        normalized_authorities = frozenset(
            _normalize_allowed_authority(authority) for authority in authorities
        )
        method_items: Iterable[str]
        if isinstance(allowed_methods, str):
            method_items = allowed_methods.split(",")
        else:
            method_items = allowed_methods

        return cls(
            allowed_hosts=frozenset(
                hostname for hostname, _ in normalized_authorities
            ),
            allow_local=allow_local,
            dns_timeout_seconds=dns_timeout_seconds,
            allowed_ports=frozenset(port for _, port in normalized_authorities),
            allowed_methods=frozenset(method_items),
            request_timeout_policy=request_timeout_policy,
            max_request_bytes=max_request_bytes,
            max_response_bytes=max_response_bytes,
            allowed_authorities=normalized_authorities,
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
        """Return whether any configured authority uses ``port``.

        This projection helper remains for compatibility and operator
        introspection. Runtime URL authorization must use :meth:`allows_authority`
        so a port intended for one host cannot be reused with another.
        """
        return (
            isinstance(port, int)
            and not isinstance(port, bool)
            and port in self.allowed_ports
        )

    def allows_authority(self, hostname: str, port: int) -> bool:
        """Return whether the exact canonical hostname and TCP port are allowed."""
        if (
            not isinstance(hostname, str)
            or not isinstance(port, int)
            or isinstance(port, bool)
        ):
            return False
        normalized_hostname = _normalize_host(hostname)
        return (normalized_hostname, port) in self.allowed_authorities

    def allows_http_method(self, method: str) -> bool:
        """Return whether ``method`` is authorized by this policy."""
        try:
            normalized = _normalize_allowed_method(method)
        except (TypeError, ValueError):
            return False
        return normalized in self.allowed_methods
