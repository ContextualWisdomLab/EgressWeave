"""Canonicalize and validate trusted EgressPolicy configuration inputs.

This internal module isolates the pure normalization layer from the immutable
policy value object. Every helper fails during trusted policy construction,
well before an outbound request can reach DNS or transport code.
"""

from __future__ import annotations

import ipaddress

import idna

DEFAULT_DNS_RESOLUTION_TIMEOUT_SECONDS = 5.0
DEFAULT_MAX_RESOLVED_ADDRESSES = 16
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


def _normalize_max_resolved_addresses(value: object) -> int:
    """Return one positive limit for unique DNS-derived connection candidates."""
    if isinstance(value, str):
        normalized = value.strip()
        if not normalized or not normalized.isascii() or not normalized.isdigit():
            raise ValueError(
                "max_resolved_addresses must be a positive decimal count"
            )
        address_count = int(normalized)
    else:
        if isinstance(value, bool) or not isinstance(value, int):
            raise TypeError("max_resolved_addresses must be an integer count")
        address_count = value

    if address_count <= 0:
        raise ValueError("max_resolved_addresses must be greater than zero")
    return address_count


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
