"""Request-boundary hardening shared by synchronous and asynchronous transports."""

from __future__ import annotations

import math
from collections.abc import Iterable, Mapping
from numbers import Real
from typing import Any

from egressweave.policy import (
    EgressPolicy,
    _normalize_allowed_method,
    _normalize_host,
)
from egressweave.timeout_policy import EgressTimeoutPolicy
from egressweave.validation import (
    EGRESS_NOT_ALLOWED,
    EgressNotAllowedError,
)

_HTTP_FIELD_NAME_OCTETS = frozenset(
    b"!#$%&'*+-.^_`|~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
)
_FORBIDDEN_OUTBOUND_REQUEST_FIELD_NAMES = frozenset(
    {
        b"connection",
        b"keep-alive",
        b"proxy-authenticate",
        b"proxy-authorization",
        b"proxy-connection",
        b"upgrade",
    }
)
_REQUEST_TIMEOUT_EXTENSION_KEYS = ("connect", "read", "write", "pool")


def _enforce_allowed_http_method(method: str, policy: EgressPolicy) -> None:
    """Reject malformed or unauthorized methods before any network I/O.

    RFC 9110 defines a request method as one case-sensitive ``token``. Policy
    configuration is intentionally normalized for operator ergonomics, but a
    request already at the transport boundary must be canonical: no leading or
    trailing whitespace, control characters, non-token octets, or alternate
    casing may be delegated to downstream HTTP parsers. This is enforced at the
    transport boundary rather than only in a builder or helper so a caller
    cannot bypass it by constructing an absolute request or reusing a returned
    client directly. ``CONNECT`` always fails because it can ask an otherwise
    allowlisted proxy to tunnel to an unvalidated destination.
    """
    try:
        normalized_method = _normalize_allowed_method(method)
    except (TypeError, ValueError) as exc:
        raise EgressNotAllowedError(EGRESS_NOT_ALLOWED) from exc

    if method != normalized_method or normalized_method not in policy.allowed_methods:
        raise EgressNotAllowedError(EGRESS_NOT_ALLOWED)


def _enforce_request_target_limit(
    target: object,
    max_request_target_bytes: int,
) -> bytes:
    """Return one exact bounded origin-form target or fail closed.

    HTTPX exposes the percent-encoded path and optional query as ``URL.raw_path``.
    Only an exact ``bytes`` value is accepted so alternate buffer protocols and
    subclasses cannot execute attacker-controlled conversion methods or change
    between validation and HTTPCore construction. Oversized values are rejected
    rather than truncated because truncation can select a different resource.
    """
    if type(target) is not bytes or len(target) > max_request_target_bytes:
        raise EgressNotAllowedError(EGRESS_NOT_ALLOWED) from None
    return target


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


def _coerce_request_header_item(item: object) -> tuple[bytes, bytes] | None:
    """Return one exact byte header pair or ``None`` without leaking failures."""
    try:
        name, value = item  # type: ignore[misc]
    except Exception:  # noqa: BLE001
        return None
    if type(name) is not bytes or type(value) is not bytes:
        return None
    return name, value


def _enforce_request_header_limits(
    headers: Iterable[tuple[bytes, bytes]],
    max_request_header_fields: int,
    max_request_header_bytes: int,
) -> None:
    """Reject final outbound fields exceeding count or name/value budgets.

    The caller authority and content-coding preferences have already been
    replaced when transports invoke this control. Counting the final list makes
    the trusted ``Host`` and ``Accept-Encoding: identity`` fields part of the
    exact outbound resource budget. Repeated fields count independently, and
    the byte budget sums every field name and value exactly once. Malformed
    metadata or an iterator failure is masked behind the generic policy boundary.
    """
    denied = False
    field_bytes = 0
    try:
        for field_count, item in enumerate(headers, start=1):
            if field_count > max_request_header_fields:
                denied = True
                break
            normalized_item = _coerce_request_header_item(item)
            if normalized_item is None:
                denied = True
                break
            name, value = normalized_item
            field_bytes += len(name) + len(value)
            if field_bytes > max_request_header_bytes:
                denied = True
                break
    except Exception:  # noqa: BLE001
        denied = True

    if denied:
        raise EgressNotAllowedError(EGRESS_NOT_ALLOWED) from None


def _validate_http_message_framing(
    content_length_values: list[bytes], transfer_encoding_values: list[bytes]
) -> None:
    """Reject ambiguous or unsupported HTTP/1.1 request-body framing.

    EgressWeave is an HTTP message sender, so it emits one unambiguous framing
    signal rather than relying on a downstream recipient to reconcile duplicate
    or conflicting fields. A single decimal ``Content-Length`` is accepted, as
    is the single ``chunked`` transfer coding generated by HTTPX for streaming
    bodies. Duplicate fields, comma-joined lengths, non-decimal lengths,
    unsupported transfer codings, and any Content-Length/Transfer-Encoding
    combination fail before connection-pool dispatch.
    """
    if (
        len(content_length_values) > 1
        or len(transfer_encoding_values) > 1
        or (content_length_values and transfer_encoding_values)
    ):
        raise EgressNotAllowedError(EGRESS_NOT_ALLOWED)

    if content_length_values:
        content_length = content_length_values[0]
        if not content_length or any(
            octet < ord("0") or octet > ord("9") for octet in content_length
        ):
            raise EgressNotAllowedError(EGRESS_NOT_ALLOWED)

    if transfer_encoding_values:
        transfer_encoding = transfer_encoding_values[0]
        if transfer_encoding.lower() != b"chunked":
            raise EgressNotAllowedError(EGRESS_NOT_ALLOWED)


def _build_safe_request_headers(
    headers: Iterable[tuple[bytes, bytes]], validated_authority: bytes
) -> list[tuple[bytes, bytes]]:
    """Validate fields, forbid protocol switching, and restore trusted ``Host``.

    HTTPX preserves raw byte headers until transport dispatch. Invalid field
    names, whitespace before the colon, control characters, duplicate or
    ambiguous host spellings, conflicting message-framing fields, connection
    controls, protocol upgrades, and proxy credentials must not be delegated to
    a downstream HTTP parser. Parser differentials around those forms have
    historically enabled request smuggling and routing confusion, while an
    Upgrade exchange can turn a validated HTTP connection into another protocol.
    Every caller-supplied field is therefore checked against RFC 9110 syntax,
    HTTP/1.1 framing is reduced to one canonical signal, protocol-switching and
    proxy-only fields are rejected, all case-insensitive ``Host`` fields are
    removed, and one validated authority is appended.
    """
    safe_headers: list[tuple[bytes, bytes]] = []
    content_length_values: list[bytes] = []
    transfer_encoding_values: list[bytes] = []

    for name, value in headers:
        if (
            not isinstance(name, bytes)
            or not name
            or any(octet not in _HTTP_FIELD_NAME_OCTETS for octet in name)
            or not isinstance(value, bytes)
            or not _is_valid_http_field_value(value)
        ):
            raise EgressNotAllowedError(EGRESS_NOT_ALLOWED)

        normalized_name = name.lower()
        if normalized_name in _FORBIDDEN_OUTBOUND_REQUEST_FIELD_NAMES:
            raise EgressNotAllowedError(EGRESS_NOT_ALLOWED)
        if normalized_name == b"content-length":
            content_length_values.append(value)
        elif normalized_name == b"transfer-encoding":
            transfer_encoding_values.append(value)

        if normalized_name != b"host":
            safe_headers.append((name, value))

    _validate_http_message_framing(content_length_values, transfer_encoding_values)
    safe_headers.append((b"host", validated_authority))
    return safe_headers


def _copy_timeout_mapping(
    raw_timeout: Mapping[object, object],
) -> dict[object, object] | None:
    """Copy untrusted timeout metadata or return ``None`` without leaking errors."""
    try:
        return dict(raw_timeout)
    except Exception:  # noqa: BLE001
        return None


def _coerce_timeout_number(value: Real) -> float | None:
    """Convert an untrusted real value or return ``None`` without leaking errors."""
    try:
        return float(value)
    except Exception:  # noqa: BLE001
        return None


def _bind_bounded_request_timeouts(
    extensions: Mapping[str, Any],
    timeout_policy: EgressTimeoutPolicy,
) -> dict[str, Any]:
    """Return request extensions with finite phase-timeout ceilings.

    HTTPX carries connect, read, write, and pool timeouts in the low-level
    ``timeout`` extension. A caller can otherwise use ``None`` to disable one or
    every phase after the destination has already passed policy validation.
    Missing or disabled values therefore receive the immutable policy maximum;
    stricter non-negative finite values are preserved and larger values are
    capped. Malformed maps, unknown keys, booleans, negative numbers, and
    non-finite values fail through the generic policy boundary before HTTPCore
    can allocate a connection or wait on network I/O. Failures raised by
    attacker-controlled mapping, key-comparison, or numeric protocol methods
    are also masked.
    """
    raw_timeout = extensions.get("timeout")
    if raw_timeout is None:
        requested_timeouts: dict[object, object] | None = {}
    elif isinstance(raw_timeout, Mapping):
        requested_timeouts = _copy_timeout_mapping(raw_timeout)
    else:
        raise EgressNotAllowedError(EGRESS_NOT_ALLOWED) from None

    if requested_timeouts is None:
        raise EgressNotAllowedError(EGRESS_NOT_ALLOWED) from None
    if any(
        type(key) is not str or key not in _REQUEST_TIMEOUT_EXTENSION_KEYS
        for key in requested_timeouts
    ):
        raise EgressNotAllowedError(EGRESS_NOT_ALLOWED) from None

    bounded_timeouts: dict[str, float] = {}
    for key, maximum in timeout_policy.as_httpcore_timeout().items():
        requested_value = requested_timeouts.get(key)
        if requested_value is None:
            bounded_timeouts[key] = maximum
            continue
        if isinstance(requested_value, bool) or not isinstance(requested_value, Real):
            raise EgressNotAllowedError(EGRESS_NOT_ALLOWED) from None
        normalized_value = _coerce_timeout_number(requested_value)
        if (
            normalized_value is None
            or not math.isfinite(normalized_value)
            or normalized_value < 0
        ):
            raise EgressNotAllowedError(EGRESS_NOT_ALLOWED) from None
        bounded_timeouts[key] = min(normalized_value, maximum)

    safe_extensions = dict(extensions)
    safe_extensions["timeout"] = bounded_timeouts
    return safe_extensions


def _bind_validated_tls_server_name(
    extensions: Mapping[str, Any], hostname: str
) -> dict[str, Any]:
    """Return safe HTTP extensions with TLS SNI bound to ``hostname``.

    HTTPX and HTTPCore expose low-level request extensions to transports. The
    ``target`` extension overrides the request target carried by the URL and can
    encode an absolute URI for forward-proxy dispatch, creating a second
    destination channel independent of the validated authority. It is therefore
    always rejected. HTTPCore ``trace`` callbacks are also rejected because
    connection-completion events can expose raw network-stream return values to
    caller code outside EgressWeave's reviewed HTTP policy surface.

    HTTPCore also honors ``sni_hostname`` while opening TLS. A caller-supplied
    value must either name the already validated host or be rejected. The
    returned copy always carries the validated hostname, preventing later
    consumers from falling back to an untrusted override.
    """
    if "target" in extensions or "trace" in extensions:
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
