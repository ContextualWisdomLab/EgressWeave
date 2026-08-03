"""URL and address validation for egressweave.

This is a faithful extraction of a production-vetted SSRF guard. Every outbound
URL is parsed, its scheme/credential/host shape checked, its hostname matched
against an explicit :class:`~egressweave.policy.EgressPolicy` allowlist, and
**every** resolved address verified to be globally routable before a connection
is ever attempted (CWE-918, Server-Side Request Forgery).

The resolved addresses are returned so the transport layer can *pin* them and
reject any post-validation host/port change — closing the validate-then-connect
TOCTOU / DNS-rebinding gap (CWE-350).
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import ipaddress
import secrets
import socket
from dataclasses import dataclass, field
from urllib.parse import SplitResult, urlsplit, urlunsplit

from egressweave.policy import EgressPolicy, _normalize_host

EGRESS_NOT_ALLOWED = "egress URL is not allowed"
_VALIDATED_EGRESS_URL_INTEGRITY_KEY = secrets.token_bytes(32)

_LOCAL_DEV_HOSTNAMES = frozenset({"localhost", "localhost.localdomain"})
_LOCAL_DEV_IP_LITERALS = frozenset({"127.0.0.1", "::1"})
_PRIVATE_LOCAL_NETWORKS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("fc00::/7"),
)


class EgressNotAllowedError(ValueError):
    """Raised when a URL or address violates the egress policy.

    Subclasses :class:`ValueError` so existing ``except ValueError`` handlers
    keep working; the message is deliberately generic and never leaks which
    specific rule rejected the target.
    """


@dataclass(frozen=True, init=False)
class ValidatedEgressURL:
    """Factory-only, tamper-evident egress result with pinned addresses."""

    normalized_url: str
    hostname: str
    port: int
    addresses: tuple[str, ...]
    _integrity_signature: bytes = field(repr=False, compare=False)

    def __init__(
        self,
        normalized_url: str,
        hostname: str,
        port: int,
        addresses: tuple[str, ...],
    ) -> None:
        raise TypeError(
            "ValidatedEgressURL objects must come from a validation function"
        )


def _validated_egress_url_signature(
    normalized_url: str,
    hostname: str,
    port: int,
    addresses: tuple[str, ...],
) -> bytes:
    """Return a process-local integrity signature for a validation result."""
    payload = repr((normalized_url, hostname, port, addresses)).encode("utf-8")
    return hmac.new(
        _VALIDATED_EGRESS_URL_INTEGRITY_KEY,
        payload,
        digestmod=hashlib.sha256,
    ).digest()


def _make_validated_egress_url(
    normalized_url: str,
    hostname: str,
    port: int,
    addresses: tuple[str, ...],
) -> ValidatedEgressURL:
    """Create and sign a result exclusively after completed validation."""
    validated = object.__new__(ValidatedEgressURL)
    object.__setattr__(validated, "normalized_url", normalized_url)
    object.__setattr__(validated, "hostname", hostname)
    object.__setattr__(validated, "port", port)
    object.__setattr__(validated, "addresses", addresses)
    object.__setattr__(
        validated,
        "_integrity_signature",
        _validated_egress_url_signature(normalized_url, hostname, port, addresses),
    )
    return validated


def _has_url_control_character(value: str) -> bool:
    return any(ord(character) < 32 or ord(character) == 127 for character in value)


def _is_ip_literal(candidate: str) -> bool:
    try:
        ipaddress.ip_address(candidate)
    except ValueError:
        return False
    return True


def _looks_like_ip_literal(candidate: str) -> bool:
    compact_candidate = candidate.replace(".", "").lower()
    return (
        ":" in candidate
        or compact_candidate.isdigit()
        or compact_candidate.startswith("0x")
    )


def _is_local_dev_host(hostname: str) -> bool:
    normalized_hostname = _normalize_host(hostname)
    return (
        normalized_hostname in _LOCAL_DEV_HOSTNAMES
        or normalized_hostname in _LOCAL_DEV_IP_LITERALS
    )


def _is_allowlisted_local_host(hostname: str, policy: EgressPolicy) -> bool:
    """Single-label allowlisted local host (Docker container name), IP literals excluded."""
    normalized_hostname = _normalize_host(hostname)
    return (
        policy.is_allowlisted_local_host(hostname)
        and not _is_ip_literal(normalized_hostname)
        and not _looks_like_ip_literal(normalized_hostname)
    )


def _is_private_local_address(
    ip_address: ipaddress.IPv4Address | ipaddress.IPv6Address,
) -> bool:
    """Whether an address is RFC 1918 or IPv6 unique-local network space.

    Do not use :attr:`ipaddress.ip_address.is_private` here: Python also marks
    documentation and benchmarking ranges as private. The local-development
    escape hatch is intentionally limited to the three RFC 1918 IPv4 blocks and
    RFC 4193 IPv6 unique-local addresses.
    """
    return any(ip_address in network for network in _PRIVATE_LOCAL_NETWORKS)


def _format_normalized_netloc(hostname: str, port: int, *, explicit_port: bool) -> str:
    host_part = f"[{hostname}]" if ":" in hostname else hostname
    if not explicit_port:
        return host_part
    return f"{host_part}:{port}"


def _validate_global_address(
    address: str, policy: EgressPolicy, *, hostname: str | None = None
) -> str:
    """Validate that an IP address is globally routable, or locally scoped.

    Local exceptions are bound to the original hostname. Built-in local names
    and loopback literals may resolve only to loopback addresses. An explicitly
    allowlisted single-label container name may resolve only to loopback or
    private network space. Dotted remote hosts never inherit either exception,
    so enabling ``allow_local`` cannot turn a DNS rebind to loopback into an
    allowed connection.
    """
    try:
        ip_address = ipaddress.ip_address(address)
    except ValueError as exc:
        raise EgressNotAllowedError(EGRESS_NOT_ALLOWED) from exc

    if hostname and _is_local_dev_host(hostname):
        if not policy.allow_local or not ip_address.is_loopback:
            raise EgressNotAllowedError(EGRESS_NOT_ALLOWED)
        return str(ip_address)

    if hostname and _is_allowlisted_local_host(hostname, policy):
        if not (ip_address.is_loopback or _is_private_local_address(ip_address)):
            raise EgressNotAllowedError(EGRESS_NOT_ALLOWED)
        return str(ip_address)

    if (
        ip_address.is_private
        or ip_address.is_loopback
        or ip_address.is_link_local
        or ip_address.is_reserved
        or ip_address.is_unspecified
        or ip_address.is_multicast
        or not ip_address.is_global
    ):
        raise EgressNotAllowedError(EGRESS_NOT_ALLOWED)
    return str(ip_address)


def _resolve_all_global_addresses(
    hostname: str, port: int, policy: EgressPolicy
) -> tuple[str, ...]:
    try:
        address_infos = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise EgressNotAllowedError(EGRESS_NOT_ALLOWED) from exc

    if not address_infos:
        raise EgressNotAllowedError(EGRESS_NOT_ALLOWED)
    addresses: list[str] = []
    seen_addresses: set[str] = set()
    for address_info in address_infos:
        # Pass the original hostname so allowlisted container names are matched
        # before checking the resolved IP.
        address = _validate_global_address(
            str(address_info[4][0]), policy, hostname=hostname
        )
        if address not in seen_addresses:
            seen_addresses.add(address)
            addresses.append(address)
    return tuple(addresses)


async def _resolve_all_global_addresses_async(
    hostname: str, port: int, policy: EgressPolicy
) -> tuple[str, ...]:
    try:
        return await asyncio.wait_for(
            asyncio.to_thread(_resolve_all_global_addresses, hostname, port, policy),
            timeout=policy.dns_timeout_seconds,
        )
    except asyncio.TimeoutError as exc:
        raise EgressNotAllowedError(EGRESS_NOT_ALLOWED) from exc


def _parse_and_validate_candidate_url(
    value: str | None,
) -> tuple[SplitResult | None, int | None]:
    if value is None:
        return None, None

    candidate = value.strip()
    if not candidate:
        return None, None

    if "\\" in candidate or _has_url_control_character(candidate):
        raise EgressNotAllowedError(EGRESS_NOT_ALLOWED)

    try:
        parsed = urlsplit(candidate)
        default_port = 443 if parsed.scheme.lower() == "https" else 80
        explicit_port = parsed.port
        if explicit_port == 0:
            raise EgressNotAllowedError(EGRESS_NOT_ALLOWED)
        port = default_port if explicit_port is None else explicit_port
        return parsed, port
    except ValueError as exc:
        raise EgressNotAllowedError(EGRESS_NOT_ALLOWED) from exc


def _validate_url_components(
    parsed: SplitResult, hostname: str, is_local_dev_host: bool, policy: EgressPolicy
) -> None:
    if parsed.scheme.lower() not in {"http", "https"}:
        raise EgressNotAllowedError(EGRESS_NOT_ALLOWED)

    if (
        parsed.scheme.lower() == "http"
        and not is_local_dev_host
        and not _is_allowlisted_local_host(hostname, policy)
    ):
        raise EgressNotAllowedError(EGRESS_NOT_ALLOWED)

    if (
        not hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise EgressNotAllowedError(EGRESS_NOT_ALLOWED)


def _validate_remote_host_is_allowed(hostname: str, policy: EgressPolicy) -> None:
    allowed_hosts = policy.allowed_hosts
    if not allowed_hosts or any("*" in allowed_host for allowed_host in allowed_hosts):
        raise EgressNotAllowedError(EGRESS_NOT_ALLOWED)
    if hostname not in allowed_hosts:
        raise EgressNotAllowedError(EGRESS_NOT_ALLOWED)
    if _is_ip_literal(hostname) or _looks_like_ip_literal(hostname):
        raise EgressNotAllowedError(EGRESS_NOT_ALLOWED)


def _normalize_egress_url(
    value: str | None, policy: EgressPolicy
) -> tuple[str | None, str | None, int | None]:
    parsed, port = _parse_and_validate_candidate_url(value)
    if parsed is None or port is None:
        return None, None, None

    hostname = _normalize_host(parsed.hostname or "")
    is_local_dev_host = _is_local_dev_host(hostname)

    _validate_url_components(parsed, hostname, is_local_dev_host, policy)

    if not is_local_dev_host:
        _validate_remote_host_is_allowed(hostname, policy)

    netloc = _format_normalized_netloc(
        hostname, port, explicit_port=parsed.port is not None
    )
    return (
        urlunsplit((parsed.scheme.lower(), netloc, parsed.path or "", "", "")),
        hostname,
        port,
    )


def _revalidate_pinned_egress_url(
    validated: ValidatedEgressURL, policy: EgressPolicy
) -> ValidatedEgressURL:
    """Re-check a caller-supplied validation result before transport use.

    The public result type has a factory-only constructor and a process-local
    integrity signature. This function verifies that signature, then restores
    every invariant established by the normal validation path without another
    DNS lookup: URL policy, canonical host and port agreement, a non-empty tuple
    of textual addresses, and per-address scope validation.
    """
    integrity_signature = getattr(validated, "_integrity_signature", None)
    if (
        not isinstance(validated, ValidatedEgressURL)
        or not isinstance(integrity_signature, bytes)
        or not isinstance(validated.normalized_url, str)
        or not isinstance(validated.hostname, str)
        or not isinstance(validated.port, int)
        or isinstance(validated.port, bool)
        or not isinstance(validated.addresses, tuple)
        or not validated.addresses
        or any(not isinstance(address, str) for address in validated.addresses)
    ):
        raise EgressNotAllowedError(EGRESS_NOT_ALLOWED)

    expected_signature = _validated_egress_url_signature(
        validated.normalized_url,
        validated.hostname,
        validated.port,
        validated.addresses,
    )
    if not hmac.compare_digest(integrity_signature, expected_signature):
        raise EgressNotAllowedError(EGRESS_NOT_ALLOWED)

    normalized_url, hostname, port = _normalize_egress_url(
        validated.normalized_url, policy
    )
    if (
        normalized_url is None
        or hostname is None
        or port is None
        or normalized_url != validated.normalized_url
        or hostname != validated.hostname
        or port != validated.port
    ):
        raise EgressNotAllowedError(EGRESS_NOT_ALLOWED)

    addresses = tuple(
        dict.fromkeys(
            _validate_global_address(address, policy, hostname=hostname)
            for address in validated.addresses
        )
    )
    return _make_validated_egress_url(normalized_url, hostname, port, addresses)


def validate_egress_url_details(
    value: str | None, *, policy: EgressPolicy
) -> ValidatedEgressURL | None:
    """Validate ``value`` against ``policy`` and resolve pinnable addresses.

    Returns ``None`` for an empty/absent URL, a :class:`ValidatedEgressURL` on
    success, and raises :class:`EgressNotAllowedError` when a non-empty URL
    violates the policy.
    """
    normalized_url, hostname, port = _normalize_egress_url(value, policy)
    if normalized_url is None or hostname is None or port is None:
        return None
    addresses = _resolve_all_global_addresses(hostname, port, policy)
    return _make_validated_egress_url(normalized_url, hostname, port, addresses)


def validate_egress_url(value: str | None, *, policy: EgressPolicy) -> str | None:
    """Return the normalized URL if it passes the policy, else ``None``."""
    validated = validate_egress_url_details(value, policy=policy)
    if validated is None:
        return None
    return validated.normalized_url


async def validate_egress_url_details_async(
    value: str | None, *, policy: EgressPolicy
) -> ValidatedEgressURL | None:
    """Async variant of :func:`validate_egress_url_details` (DNS off the loop)."""
    normalized_url, hostname, port = _normalize_egress_url(value, policy)
    if normalized_url is None or hostname is None or port is None:
        return None
    addresses = await _resolve_all_global_addresses_async(hostname, port, policy)
    return _make_validated_egress_url(normalized_url, hostname, port, addresses)


async def validate_egress_url_async(
    value: str | None, *, policy: EgressPolicy
) -> str | None:
    """Async variant of :func:`validate_egress_url`."""
    validated = await validate_egress_url_details_async(value, policy=policy)
    if validated is None:
        return None
    return validated.normalized_url
