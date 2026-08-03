"""Request-boundary hardening shared by synchronous and asynchronous transports."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from egressweave.policy import EgressPolicy, _normalize_host
from egressweave.validation import (
    EGRESS_NOT_ALLOWED,
    EgressNotAllowedError,
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


def _bind_validated_tls_server_name(
    extensions: Mapping[str, Any], hostname: str
) -> dict[str, Any]:
    """Return copied HTTP extensions with TLS SNI bound to ``hostname``.

    HTTPX exposes low-level request extensions to transports, and httpcore
    honors ``sni_hostname`` while opening TLS. A caller-supplied value is an
    independent authority channel, so it must either name the already
    validated host or be rejected. The returned copy always carries the
    validated hostname, preventing later consumers from falling back to an
    untrusted override.
    """
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
