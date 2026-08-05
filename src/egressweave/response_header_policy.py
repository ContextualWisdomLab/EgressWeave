"""Public policy extension for finite response-header resource budgets.

The extension is isolated from the established policy implementation so the
pre-1.0 positional constructor remains stable while response metadata limits
are added at the end of the immutable value object. Package initialization
publishes this class through :mod:`egressweave.policy` and the package root.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from egressweave._policy_normalization import (
    DEFAULT_ALLOWED_EGRESS_PORTS,
    DEFAULT_ALLOWED_HTTP_METHODS,
    DEFAULT_DNS_RESOLUTION_TIMEOUT_SECONDS,
    DEFAULT_MAX_REQUEST_BYTES,
    DEFAULT_MAX_RESOLVED_ADDRESSES,
    DEFAULT_MAX_RESPONSE_BYTES,
    DEFAULT_MAX_RESPONSE_HEADER_BYTES,
    DEFAULT_MAX_RESPONSE_HEADER_FIELDS,
    _normalize_allowed_authority,
    _normalize_max_response_header_bytes,
    _normalize_max_response_header_fields,
)
from egressweave.policy import EgressPolicy as _BaseEgressPolicy
from egressweave.timeout_policy import (
    DEFAULT_EGRESS_TIMEOUT_POLICY,
    EgressTimeoutPolicy,
)


@dataclass(frozen=True)
class EgressPolicy(_BaseEgressPolicy):
    """Immutable egress policy with finite response-header metadata limits.

    ``max_response_header_fields`` bounds separate decoded response fields.
    Repeated fields, including ``Set-Cookie``, count independently.
    ``max_response_header_bytes`` bounds the cumulative bytes in decoded field
    names and values. Both limits are positive, finite, normalized during
    trusted policy construction, and appended after all established dataclass
    fields to preserve positional compatibility.
    """

    max_response_header_fields: int = DEFAULT_MAX_RESPONSE_HEADER_FIELDS
    max_response_header_bytes: int = DEFAULT_MAX_RESPONSE_HEADER_BYTES

    def __post_init__(self) -> None:
        """Normalize the base policy and both response-header budgets."""
        super().__post_init__()
        object.__setattr__(
            self,
            "max_response_header_fields",
            _normalize_max_response_header_fields(
                self.max_response_header_fields
            ),
        )
        object.__setattr__(
            self,
            "max_response_header_bytes",
            _normalize_max_response_header_bytes(self.max_response_header_bytes),
        )

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
    ) -> EgressPolicy:
        """Build an unambiguous policy from host and port projections."""
        host_items = hosts.split(",") if isinstance(hosts, str) else hosts
        port_items = (
            allowed_ports.split(",")
            if isinstance(allowed_ports, str)
            else allowed_ports
        )
        method_items = (
            allowed_methods.split(",")
            if isinstance(allowed_methods, str)
            else allowed_methods
        )
        return cls(
            allowed_hosts=frozenset(host_items),
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
    ) -> EgressPolicy:
        """Build a policy from exact normalized ``(hostname, port)`` pairs."""
        normalized_authorities = frozenset(
            _normalize_allowed_authority(authority) for authority in authorities
        )
        method_items = (
            allowed_methods.split(",")
            if isinstance(allowed_methods, str)
            else allowed_methods
        )
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
            allowed_authorities=normalized_authorities,
        )


EgressPolicy.__module__ = "egressweave.policy"
