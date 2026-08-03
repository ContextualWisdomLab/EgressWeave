"""Synchronous DNS-pinned HTTPX transport for egressweave.

This module provides the blocking counterpart to the asynchronous transport.
Every connection is restricted to addresses returned by the normal egress
validation path, each pinned address is rechecked immediately before connect,
and request authority drift is rejected before reaching the connection pool.
"""

from __future__ import annotations

import time
from collections.abc import Iterable
from urllib.parse import urlsplit

import httpcore
import httpx
from httpx._config import DEFAULT_LIMITS, create_ssl_context
from httpx._transports.default import ResponseStream, map_httpcore_exceptions

from egressweave.policy import EgressPolicy
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
                # Backends expose several connection exception classes. A
                # failed address must not prevent a later validated candidate
                # from succeeding, but the final backend error remains useful.
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

    def __init__(self, validated: ValidatedEgressURL, policy: EgressPolicy) -> None:
        """Revalidate caller-supplied state and construct a pinned connection pool."""
        self._validated = _revalidate_pinned_egress_url(validated, policy)
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
        """Reject request authority drift before the request reaches the pool."""
        parsed_url = urlsplit(self._validated.normalized_url)
        request_scheme = request.url.scheme.lower()
        request_host = request.url.host.lower().rstrip(".")
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
        """Send one request after restoring the validated authority and Host header."""
        self._verify_request_target(request)
        parsed_url = urlsplit(self._validated.normalized_url)
        safe_headers = [
            (key, value)
            for key, value in request.headers.raw
            if key.lower() != b"host"
        ]
        safe_headers.append((b"host", parsed_url.netloc.encode("ascii")))

        core_request = httpcore.Request(
            method=request.method,
            url=httpcore.URL(
                scheme=parsed_url.scheme.encode("ascii"),
                host=self._validated.hostname.encode("ascii"),
                port=self._validated.port,
                target=request.url.raw_path,
            ),
            headers=safe_headers,
            content=request.stream,
            extensions=request.extensions,
        )
        with map_httpcore_exceptions():
            response = self._pool.handle_request(core_request)

        return httpx.Response(
            status_code=response.status,
            headers=response.headers,
            stream=ResponseStream(response.stream),
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
    :class:`~egressweave.validation.EgressNotAllowedError`.
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
    connection is then pinned to its addresses, and any forged result or
    post-validation authority change is rejected before network I/O.
    """
    return httpx.Client(
        follow_redirects=False,
        trust_env=False,
        transport=_PinnedEgressTransport(validated, policy),
    )
