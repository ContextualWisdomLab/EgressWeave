"""Synchronous DNS-pinned HTTPX transport for egressweave.

This module provides the blocking counterpart to the asynchronous transport.
Every connection is restricted to addresses returned by the normal egress
validation path, each pinned address is rechecked immediately before connect,
request authority drift is rejected before reaching the connection pool, and
both outbound request bodies and identity-coded response bodies are bounded by
the injected egress policy.
"""

from __future__ import annotations

import time
from collections.abc import Iterable
from urllib.parse import urlsplit

import httpcore
import httpx
from httpx._config import DEFAULT_LIMITS, create_ssl_context
from httpx._transports.default import ResponseStream, map_httpcore_exceptions

from egressweave.policy import EgressPolicy, _normalize_host
from egressweave.request_body_safety import (
    _BoundedSyncRequestStream,
    _enforce_declared_request_size,
)
from egressweave.request_safety import (
    _bind_validated_tls_server_name,
    _build_safe_request_headers,
    _enforce_allowed_http_method,
)
from egressweave.response_safety import (
    _BoundedSyncResponseStream,
    _enforce_declared_response_size,
    _force_identity_accept_encoding,
)
from egressweave.validation import (
    EGRESS_NOT_ALLOWED,
    EgressNotAllowedError,
    ValidatedEgressURL,
    _revalidate_pinned_egress_url,
    _validate_global_address,
    validate_egress_url_details,
)

SocketOption = (
    tuple[int, int, int]
    | tuple[int, int, bytes | bytearray]
    | tuple[int, int, None, int]
)


class _DenyAllSyncTransport(httpx.BaseTransport):
    """Fail-closed transport used when no outbound authority was validated."""

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        """Reject every request before any network or proxy code can run."""
        raise EgressNotAllowedError(EGRESS_NOT_ALLOWED)

    def close(self) -> None:
        """Close the stateless deny transport."""


class _PinnedEgressSyncNetworkBackend(httpcore.NetworkBackend):
    """Open synchronous TCP connections only to prevalidated IP addresses."""

    def __init__(
        self,
        hostname: str,
        port: int,
        addresses: tuple[str, ...],
        policy: EgressPolicy,
    ) -> None:
        """Store the validated authority and defensively recheck every address."""
        if not addresses:
            raise EgressNotAllowedError(EGRESS_NOT_ALLOWED)
        self._hostname = hostname
        self._port = port
        self._policy = policy
        self._addresses = tuple(
            _validate_global_address(address, policy, hostname=hostname)
            for address in addresses
        )
        self._backend = httpcore.SyncBackend()

    def _verify_host_port(self, host: str | bytes, port: int) -> None:
        """Reject any authority change after URL validation."""
        host_text = host.decode("ascii") if isinstance(host, bytes) else str(host)
        normalized_host = host_text.lower().rstrip(".")
        if normalized_host != self._hostname or int(port) != self._port:
            raise OSError("egress URL host changed after validation")

    def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Iterable[SocketOption] | None = None,
    ) -> httpcore.NetworkStream:
        """Connect to the first working pinned address within one timeout budget."""
        self._verify_host_port(host, port)
        deadline = None if timeout is None else time.monotonic() + max(timeout, 0.0)
        last_error: Exception | None = None

        for address in self._addresses:
            pinned_address = _validate_global_address(
                address, self._policy, hostname=self._hostname
            )
            remaining_timeout = None
            if deadline is not None:
                remaining_timeout = max(0.0, deadline - time.monotonic())
            try:
                return self._backend.connect_tcp(
                    pinned_address,
                    port,
                    timeout=remaining_timeout,
                    local_address=local_address,
                    socket_options=socket_options,
                )
            except Exception as exc:  # noqa: BLE001
                last_error = exc

        if last_error is not None:
            raise last_error
        raise OSError(EGRESS_NOT_ALLOWED)

    def connect_unix_socket(
        self,
        path: str,
        timeout: float | None = None,
        socket_options: Iterable[SocketOption] | None = None,
    ) -> httpcore.NetworkStream:
        """Refuse Unix sockets because they bypass hostname policy enforcement."""
        raise OSError("egress URL must not use Unix sockets")


class _PinnedEgressTransport(httpx.BaseTransport):
    """Synchronous HTTPX transport pinned to one validated URL authority."""

    _policy = EgressPolicy(allowed_hosts=frozenset())

    def __init__(self, validated: ValidatedEgressURL, policy: EgressPolicy) -> None:
        """Revalidate caller-supplied state and construct a pinned connection pool."""
        self._validated = _revalidate_pinned_egress_url(validated, policy)
        self._policy = policy
        ssl_context = create_ssl_context(verify=True, trust_env=False)
        self._pool = httpcore.ConnectionPool(
            ssl_context=ssl_context,
            max_connections=DEFAULT_LIMITS.max_connections,
            max_keepalive_connections=DEFAULT_LIMITS.max_keepalive_connections,
            keepalive_expiry=DEFAULT_LIMITS.keepalive_expiry,
            http1=True,
            http2=False,
            network_backend=_PinnedEgressSyncNetworkBackend(
                self._validated.hostname,
                self._validated.port,
                self._validated.addresses,
                policy,
            ),
        )

    def _verify_request_target(self, request: httpx.Request) -> None:
        """Reject method or authority drift before the request reaches the pool."""
        _enforce_allowed_http_method(request.method, self._policy)
        parsed_url = urlsplit(self._validated.normalized_url)
        request_scheme = request.url.scheme.lower()
        request_host = _normalize_host(request.url.host)
        request_port = request.url.port
        if request_port is None:
            request_port = {"http": 80, "https": 443}.get(request_scheme)

        if (
            request.url.userinfo
            or request_scheme != parsed_url.scheme
            or request_host != self._validated.hostname
            or request_port != self._validated.port
        ):
            raise EgressNotAllowedError(EGRESS_NOT_ALLOWED)

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        """Send one framing-exact bounded request and return a bounded response."""
        self._verify_request_target(request)
        parsed_url = urlsplit(self._validated.normalized_url)
        safe_extensions = _bind_validated_tls_server_name(
            request.extensions, self._validated.hostname
        )
        safe_headers = _force_identity_accept_encoding(
            _build_safe_request_headers(
                request.headers.raw, parsed_url.netloc.encode("ascii")
            )
        )
        try:
            declared_request_bytes = _enforce_declared_request_size(
                safe_headers, self._policy.max_request_bytes
            )
        except EgressNotAllowedError:
            try:
                request.stream.close()
            except Exception:  # noqa: BLE001, S110
                pass
            raise EgressNotAllowedError(EGRESS_NOT_ALLOWED) from None

        core_request = httpcore.Request(
            method=request.method,
            url=httpcore.URL(
                scheme=parsed_url.scheme.encode("ascii"),
                host=self._validated.hostname.encode("ascii"),
                port=self._validated.port,
                target=request.url.raw_path,
            ),
            headers=safe_headers,
            content=_BoundedSyncRequestStream(
                request.stream,
                self._policy.max_request_bytes,
                declared_request_bytes,
            ),
            extensions=safe_extensions,
        )
        with map_httpcore_exceptions():
            response = self._pool.handle_request(core_request)

        try:
            _enforce_declared_response_size(
                request.method,
                response.status,
                response.headers,
                self._policy.max_response_bytes,
            )
        except EgressNotAllowedError:
            try:
                response.stream.close()
            finally:
                raise

        return httpx.Response(
            status_code=response.status,
            headers=response.headers,
            stream=_BoundedSyncResponseStream(
                ResponseStream(response.stream), self._policy.max_response_bytes
            ),
            extensions=response.extensions,
        )

    def close(self) -> None:
        """Close the underlying pinned connection pool."""
        self._pool.close()


def build_egress_sync_client(
    base_url: str | None, *, policy: EgressPolicy
) -> tuple[str | None, httpx.Client]:
    """Validate ``base_url`` and return a synchronous fail-closed HTTPX client.

    Returns ``(normalized_url, client)``. When ``base_url`` is empty or absent,
    the normalized URL is ``None`` and the returned client rejects every
    request before network I/O. A non-empty URL that violates the policy raises
    :class:`~egressweave.validation.EgressNotAllowedError`. Request bodies are
    limited to ``policy.max_request_bytes`` and must match a supplied
    ``Content-Length`` exactly. Successful response bodies are requested with
    identity coding and limited to ``policy.max_response_bytes`` during
    streaming and buffered reads.
    """
    validated = validate_egress_url_details(base_url, policy=policy)
    if validated is None:
        return (
            None,
            httpx.Client(
                follow_redirects=False,
                trust_env=False,
                transport=_DenyAllSyncTransport(),
            ),
        )
    return (
        validated.normalized_url,
        httpx.Client(
            follow_redirects=False,
            trust_env=False,
            transport=_PinnedEgressTransport(validated, policy),
        ),
    )


def build_pinned_https_client(
    validated: ValidatedEgressURL, *, policy: EgressPolicy
) -> httpx.Client:
    """Build a synchronous DNS-pinned HTTPX client from validated URL state.

    The supplied result is revalidated without another DNS lookup. Every
    connection is pinned to its addresses, any forged result or authority change
    is rejected before network I/O, every outbound request body is constrained
    by ``policy.max_request_bytes`` and exact declared framing, and every
    identity-coded response body is constrained by
    ``policy.max_response_bytes``.
    """
    return httpx.Client(
        follow_redirects=False,
        trust_env=False,
        transport=_PinnedEgressTransport(validated, policy),
    )
