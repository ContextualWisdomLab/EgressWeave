"""Egress policy — the single injected dependency for egressweave.

The policy decouples the SSRF / DNS-rebinding guard from any one
application's settings object. It carries exact host-and-port authorities, the
HTTP methods those authorities may receive, finite DNS-candidate, request-target,
request-body, request-header, response-header, and response-body budgets, finite
request-phase timeout ceilings, finite connection-pool capacity, and an
``allow_local`` escape hatch for local
development stacks: built-in local names are bound to loopback, while explicit
Docker-container names may resolve to RFC 1918 or RFC 4193 addresses.

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

import math
from collections.abc import Iterable
from dataclasses import dataclass
from numbers import Real

from egressweave._policy_normalization import (
    DEFAULT_ALLOWED_EGRESS_PORTS,
    DEFAULT_ALLOWED_HTTP_METHODS,
    DEFAULT_DNS_RESOLUTION_TIMEOUT_SECONDS,
    DEFAULT_MAX_REQUEST_BYTES,
    DEFAULT_MAX_REQUEST_HEADER_BYTES,
    DEFAULT_MAX_REQUEST_HEADER_FIELDS,
    DEFAULT_MAX_REQUEST_TARGET_BYTES,
    DEFAULT_MAX_RESOLVED_ADDRESSES,
    DEFAULT_MAX_RESPONSE_BYTES,
    DEFAULT_MAX_RESPONSE_HEADER_BYTES,
    DEFAULT_MAX_RESPONSE_HEADER_FIELDS,
    _normalize_allowed_authority,
    _normalize_allowed_host,
    _normalize_allowed_method,
    _normalize_allowed_port,
    _normalize_host,
    _normalize_max_request_bytes,
    _normalize_max_request_header_bytes,
    _normalize_max_request_header_fields,
    _normalize_max_request_target_bytes,
    _normalize_max_resolved_addresses,
    _normalize_max_response_bytes,
    _normalize_max_response_header_bytes,
    _normalize_max_response_header_fields,
)
from egressweave.connection_pool_policy import (
    DEFAULT_EGRESS_CONNECTION_POOL_POLICY,
    EgressConnectionPoolPolicy,
)
from egressweave.timeout_policy import (
    DEFAULT_EGRESS_TIMEOUT_POLICY,
    EgressTimeoutPolicy,
)


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

    ``max_resolved_addresses`` limits the number of unique validated addresses
    one DNS answer may contribute to a pinned result. The finite default bounds
    retained memory and later TCP attempts. Duplicate resolver rows do not
    consume additional capacity, while an answer containing more unique
    candidates fails closed instead of silently truncating resolver preference.

    ``allowed_methods`` is the exhaustive set of HTTP methods that pinned
    clients may dispatch. The secure default covers ordinary API operations but
    excludes TRACE, WebDAV extension methods, and every other unrequested method.
    ``CONNECT`` is always invalid because it can ask an allowlisted proxy to open
    a tunnel to a second, unvalidated destination.

    ``request_timeout_policy`` caps the connect, read, write, and pool timeout
    values delegated to HTTPCore. Missing or explicitly disabled request values
    receive the finite policy maximum, while stricter caller values are retained.

    ``connection_pool_policy`` bounds concurrent connections, retained idle
    connections, and idle connection lifetime for both pinned transports. The
    immutable provider-neutral object replaces reliance on HTTPX private defaults
    and lets each integration choose stricter finite capacity.

    ``max_request_bytes`` is the largest outbound request body a returned client
    will consume from its caller. The finite 16 MiB default rejects an oversized
    declared length before pool dispatch and also counts actual synchronous or
    asynchronous stream bytes, including chunked and under-declared content.

    ``max_request_header_fields`` is the largest number of final outbound fields
    a returned client will dispatch after replacing caller authority and content-
    coding preferences. ``max_request_header_bytes`` is the cumulative byte count
    of those final field names and values. The finite defaults bound credential,
    tracing, cookie, and custom metadata fanout before connection-pool dispatch.

    ``max_request_target_bytes`` is the largest exact origin-form request target
    delegated to HTTPCore, measured over HTTPX's percent-encoded ``raw_path``
    bytes including an optional query. The finite 8 KiB default rejects excess
    path or query bytes before connection-pool dispatch and never truncates a
    target, because truncation could select a different resource.

    ``max_response_header_fields`` is the largest number of separate response
    fields a returned client will expose. Repeated fields, including
    ``Set-Cookie``, count independently. ``max_response_header_bytes`` is the
    cumulative byte count of decoded field names and values. The finite defaults
    bound metadata fanout and oversized diagnostic or cookie fields before a
    response becomes caller-visible.

    ``max_response_bytes`` is the largest decoded response body a returned
    client will expose. The finite 16 MiB default protects ordinary JSON API
    integrations from an allowlisted but compromised or attacker-controlled
    authority returning an unbounded body. Operators can choose smaller or
    larger positive resource budgets for a specific integration, but cannot
    disable a boundary with zero, a negative value, a boolean, or malformed text.
    """

    allowed_hosts: frozenset[str]
    allow_local: bool = False
    dns_timeout_seconds: float = DEFAULT_DNS_RESOLUTION_TIMEOUT_SECONDS
    allowed_ports: frozenset[int] = DEFAULT_ALLOWED_EGRESS_PORTS
    allowed_methods: frozenset[str] = DEFAULT_ALLOWED_HTTP_METHODS
    max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES
    allowed_authorities: frozenset[tuple[str, int]] | None = None
    max_request_bytes: int = DEFAULT_MAX_REQUEST_BYTES
    max_resolved_addresses: int = DEFAULT_MAX_RESOLVED_ADDRESSES
    request_timeout_policy: EgressTimeoutPolicy = DEFAULT_EGRESS_TIMEOUT_POLICY
    max_response_header_fields: int = DEFAULT_MAX_RESPONSE_HEADER_FIELDS
    max_response_header_bytes: int = DEFAULT_MAX_RESPONSE_HEADER_BYTES
    max_request_header_fields: int = DEFAULT_MAX_REQUEST_HEADER_FIELDS
    max_request_header_bytes: int = DEFAULT_MAX_REQUEST_HEADER_BYTES
    max_request_target_bytes: int = DEFAULT_MAX_REQUEST_TARGET_BYTES
    connection_pool_policy: EgressConnectionPoolPolicy = (
        DEFAULT_EGRESS_CONNECTION_POOL_POLICY
    )

    def __post_init__(self) -> None:
        """Validate and canonicalize every immutable policy field."""
        if not isinstance(self.allow_local, bool):
            raise TypeError("allow_local must be a boolean")
        if not isinstance(self.request_timeout_policy, EgressTimeoutPolicy):
            raise TypeError(
                "request_timeout_policy must be an EgressTimeoutPolicy"
            )
        if not isinstance(
            self.connection_pool_policy, EgressConnectionPoolPolicy
        ):
            raise TypeError(
                "connection_pool_policy must be an EgressConnectionPoolPolicy"
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
        normalized_max_resolved_addresses = _normalize_max_resolved_addresses(
            self.max_resolved_addresses
        )
        normalized_max_request_bytes = _normalize_max_request_bytes(
            self.max_request_bytes
        )
        normalized_max_response_bytes = _normalize_max_response_bytes(
            self.max_response_bytes
        )
        normalized_max_response_header_fields = (
            _normalize_max_response_header_fields(
                self.max_response_header_fields
            )
        )
        normalized_max_response_header_bytes = (
            _normalize_max_response_header_bytes(self.max_response_header_bytes)
        )
        normalized_max_request_header_fields = (
            _normalize_max_request_header_fields(
                self.max_request_header_fields
            )
        )
        normalized_max_request_header_bytes = (
            _normalize_max_request_header_bytes(self.max_request_header_bytes)
        )
        normalized_max_request_target_bytes = _normalize_max_request_target_bytes(
            self.max_request_target_bytes
        )

        # Frozen dataclass: bypass the immutability guard exactly once per field
        # to store normalized caller input and canonical scalar values.
        object.__setattr__(self, "allowed_hosts", frozenset(normalized_hosts))
        object.__setattr__(self, "dns_timeout_seconds", float(timeout))
        object.__setattr__(
            self,
            "max_resolved_addresses",
            normalized_max_resolved_addresses,
        )
        object.__setattr__(self, "allowed_ports", frozenset(normalized_ports))
        object.__setattr__(self, "allowed_methods", normalized_methods)
        object.__setattr__(self, "max_request_bytes", normalized_max_request_bytes)
        object.__setattr__(self, "max_response_bytes", normalized_max_response_bytes)
        object.__setattr__(
            self,
            "max_response_header_fields",
            normalized_max_response_header_fields,
        )
        object.__setattr__(
            self,
            "max_response_header_bytes",
            normalized_max_response_header_bytes,
        )
        object.__setattr__(
            self,
            "max_request_header_fields",
            normalized_max_request_header_fields,
        )
        object.__setattr__(
            self,
            "max_request_header_bytes",
            normalized_max_request_header_bytes,
        )
        object.__setattr__(
            self,
            "max_request_target_bytes",
            normalized_max_request_target_bytes,
        )
        object.__setattr__(self, "allowed_authorities", normalized_authorities)

    @classmethod
    def from_hosts(
        cls,
        hosts: str | Iterable[str],
        *,
        allow_local: bool = False,
        dns_timeout_seconds: float = DEFAULT_DNS_RESOLUTION_TIMEOUT_SECONDS,
        max_resolved_addresses: int | str = DEFAULT_MAX_RESOLVED_ADDRESSES,
        allowed_ports: str | Iterable[int | str] = DEFAULT_ALLOWED_EGRESS_PORTS,
        allowed_methods: str | Iterable[str] = DEFAULT_ALLOWED_HTTP_METHODS,
        request_timeout_policy: EgressTimeoutPolicy = DEFAULT_EGRESS_TIMEOUT_POLICY,
        max_request_bytes: int | str = DEFAULT_MAX_REQUEST_BYTES,
        max_response_bytes: int | str = DEFAULT_MAX_RESPONSE_BYTES,
        max_response_header_fields: int | str = (
            DEFAULT_MAX_RESPONSE_HEADER_FIELDS
        ),
        max_response_header_bytes: int | str = (
            DEFAULT_MAX_RESPONSE_HEADER_BYTES
        ),
        max_request_header_fields: int | str = (
            DEFAULT_MAX_REQUEST_HEADER_FIELDS
        ),
        max_request_header_bytes: int | str = (
            DEFAULT_MAX_REQUEST_HEADER_BYTES
        ),
        max_request_target_bytes: int | str = DEFAULT_MAX_REQUEST_TARGET_BYTES,
        connection_pool_policy: EgressConnectionPoolPolicy = (
            DEFAULT_EGRESS_CONNECTION_POOL_POLICY
        ),
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
            max_resolved_addresses=max_resolved_addresses,
            allowed_ports=frozenset(port_items),
            allowed_methods=frozenset(method_items),
            request_timeout_policy=request_timeout_policy,
            max_request_bytes=max_request_bytes,
            max_response_bytes=max_response_bytes,
            max_response_header_fields=max_response_header_fields,
            max_response_header_bytes=max_response_header_bytes,
            max_request_header_fields=max_request_header_fields,
            max_request_header_bytes=max_request_header_bytes,
            max_request_target_bytes=max_request_target_bytes,
            connection_pool_policy=connection_pool_policy,
        )

    @classmethod
    def from_authorities(
        cls,
        authorities: Iterable[tuple[str, int | str]],
        *,
        allow_local: bool = False,
        dns_timeout_seconds: float = DEFAULT_DNS_RESOLUTION_TIMEOUT_SECONDS,
        max_resolved_addresses: int | str = DEFAULT_MAX_RESOLVED_ADDRESSES,
        allowed_methods: str | Iterable[str] = DEFAULT_ALLOWED_HTTP_METHODS,
        request_timeout_policy: EgressTimeoutPolicy = DEFAULT_EGRESS_TIMEOUT_POLICY,
        max_request_bytes: int | str = DEFAULT_MAX_REQUEST_BYTES,
        max_response_bytes: int | str = DEFAULT_MAX_RESPONSE_BYTES,
        max_response_header_fields: int | str = (
            DEFAULT_MAX_RESPONSE_HEADER_FIELDS
        ),
        max_response_header_bytes: int | str = (
            DEFAULT_MAX_RESPONSE_HEADER_BYTES
        ),
        max_request_header_fields: int | str = (
            DEFAULT_MAX_REQUEST_HEADER_FIELDS
        ),
        max_request_header_bytes: int | str = (
            DEFAULT_MAX_REQUEST_HEADER_BYTES
        ),
        max_request_target_bytes: int | str = DEFAULT_MAX_REQUEST_TARGET_BYTES,
        connection_pool_policy: EgressConnectionPoolPolicy = (
            DEFAULT_EGRESS_CONNECTION_POOL_POLICY
        ),
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
            max_resolved_addresses=max_resolved_addresses,
            allowed_ports=frozenset(port for _, port in normalized_authorities),
            allowed_methods=frozenset(method_items),
            request_timeout_policy=request_timeout_policy,
            max_request_bytes=max_request_bytes,
            max_response_bytes=max_response_bytes,
            max_response_header_fields=max_response_header_fields,
            max_response_header_bytes=max_response_header_bytes,
            max_request_header_fields=max_request_header_fields,
            max_request_header_bytes=max_request_header_bytes,
            max_request_target_bytes=max_request_target_bytes,
            connection_pool_policy=connection_pool_policy,
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
