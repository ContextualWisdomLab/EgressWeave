"""Request-boundary hardening shared by synchronous and asynchronous transports."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

from egressweave.policy import EgressPolicy, _normalize_host
from egressweave.validation import (
    EGRESS_NOT_ALLOWED,
    EgressNotAllowedError,
)

_HTTP_FIELD_NAME_OCTETS = frozenset(
    b"!#$%&'*+-.^_`|~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
)


def _enforce_allowed_http_method(method: str, policy: EgressPolicy) -> None:
    """Reject request methods outside the policy before any network I/O.

    This is enforced at the transport boundary rather than only in a builder or
    helper so a caller cannot bypass it by constructing an absolute request or
    reusing a returned client directly. ``CONNECT`` always fails because it can
    ask an otherwise allowlisted proxy to tunnel to an unvalidated destination.
    """
    if not policy.allows_http_method(method):
        raise EgressNotAllowedError(EGRESS_NOT_ALLOWED)


def _is_valid_http_field_value(value: bytes) -> bool:
    """Return whether ``value`` is one normalized RFC 9110 field value.

    Field values may be empty and may contain visible ASCII, internal SP/HTAB,
    or opaque ``obs-text`` octets. Leading/trailing whitespace and every other
    control octet are rejected so downstream parsers cannot disagree about the
    field boundary or value.
    """
    if value[:1] in {b" ", b"\t"} or value[-1:] in {b" ", b"\t"}:
        return False
    return all(
        octet == 9 or 32 <= octet <= 126 or 128 <= octet <= 255 for octet in value
    )


def _build_safe_request_headers(
    headers: Iterable[tuple[bytes, bytes]], validated_authority: bytes
) -> list[tuple[bytes, bytes]]:
    """Validate field syntax and restore exactly one trusted ``Host`` field.

    HTTPX preserves raw byte headers until transport dispatch. Invalid field
    names, whitespace before the colon, control characters, and duplicate or
    ambiguous host spellings must not be delegated to a downstream HTTP parser:
    parser differentials around those forms have historically enabled request
    smuggling and routing confusion. Every caller-supplied field is therefore
    checked against RFC 9110 syntax, all case-insensitive ``Host`` fields are
    removed, and one validated authority is appended.
    """
    safe_headers: list[tuple[bytes, bytes]] = []
    for name, value in headers:
        if (
            not isinstance(name, bytes)
            or not name
            or any(octet not in _HTTP_FIELD_NAME_OCTETS for octet in name)
            or not isinstance(value, bytes)
            or not _is_valid_http_field_value(value)
        ):
            raise EgressNotAllowedError(EGRESS_NOT_ALLOWED)
        if name.lower() != b"host":
            safe_headers.append((name, value))

    safe_headers.append((b"host", validated_authority))
    return safe_headers


def _bind_validated_tls_server_name(
    extensions: Mapping[str, Any], hostname: str
) -> dict[str, Any]:
    """Return safe HTTP extensions with TLS SNI bound to ``hostname``.

    HTTPX and HTTPCore expose low-level request extensions to transports. The
    ``target`` extension overrides the request target carried by the URL and can
    encode an absolute URI for forward-proxy dispatch, creating a second
    destination channel independent of the validated authority. It is therefore
    always rejected.

    HTTPCore also honors ``sni_hostname`` while opening TLS. A caller-supplied
    value must either name the already validated host or be rejected. The
    returned copy always carries the validated hostname, preventing later
    consumers from falling back to an untrusted override.
    """
    if "target" in extensions:
        raise EgressNotAllowedError(EGRESS_NOT_ALLOWED)

    requested_server_name = extensions.get("sni_hostname")
    if requested_server_name is not None:
        if isinstance(requested_server_name, bytes):
            try:
                requested_server_name_text = requested_server_name.decode("ascii")
            except UnicodeDecodeError as exc:
                raise EgressNotAllowedError(EGRESS_NOT_ALLOWED) from exc
        elif isinstance(requested_server_name, str):
            requested_server_name_text = requested_server_name
        else:
            raise EgressNotAllowedError(EGRESS_NOT_ALLOWED)

        if _normalize_host(requested_server_name_text) != hostname:
            raise EgressNotAllowedError(EGRESS_NOT_ALLOWED)

    safe_extensions = dict(extensions)
    safe_extensions["sni_hostname"] = hostname
    return safe_extensions
