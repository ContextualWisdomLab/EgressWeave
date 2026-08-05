"""DNS-pinned httpx transport for egressweave.

Validation alone is not enough: between the moment a hostname is resolved and
checked and the moment a connection is opened, the DNS answer can change so the
socket lands on a private address the check never saw (CWE-350, DNS rebinding /
a validate-then-connect TOCTOU).

This transport closes that gap. Every outbound connection is pinned to the exact
addresses returned at validation time, each address is re-validated against the
policy immediately before ``connect``, and any host/port that differs from the
validated one is rejected. Redirects are disabled, environment proxies ignored
(``trust_env=False``), Unix sockets refused, outbound request targets, headers,
and streams are bounded and tied to exact framing, request-phase waits are
capped, response header metadata is bounded, and identity-coded response bodies
are bounded by the injected policy.

The transport depends on a few httpx / httpcore internals; those libraries are
version-pinned in ``pyproject.toml`` and exercised by the test-suite so an
upgrade that moves them is caught before release.
"""

from __future__ import annotations

import asyncio
from urllib.parse import urlsplit

import httpcore
import httpx
from httpcore._backends.auto import AutoBackend
from httpx._config import DEFAULT_LIMITS
from httpx._transports.default import AsyncResponseStream, map_httpcore_exceptions

from egressweave.policy import EgressPolicy, _normalize_host
from egressweave.request_body_safety import (
    _BoundedAsyncRequestStream,
    _enforce_declared_request_size,
)
from egressweave.request_safety import (
    _bind_bounded_request_timeouts,
    _bind_validated_tls_server_name,
    _build_safe_request_headers,
    _enforce_allowed_http_method,
    _enforce_request_header_limits,
    _enforce_request_target_limit,
)
from egressweave.response_safety import (
    _BoundedAsyncResponseStream,
    _enforce_declared_response_size,
    _enforce_response_header_limits,
    _force_identity_accept_encoding,
)
from egressweave.tls import TLSConfiguration, create_egress_ssl_context
from egressweave.validation import (
    EGRESS_NOT_ALLOWED,
    EgressNotAllowedError,
    ValidatedEgressURL,
    _revalidate_pinned_egress_url,
    _validate_global_address,
    validate_egress_url_details_async,
)

_CONNECTION_ATTEMPT_DELAY_SECONDS = 0.25


class _DenyAllAsyncTransport(httpx.AsyncBaseTransport):
    """Fail-closed transport used when no outbound authority was validated."""

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        """Reject every request before any network or proxy code can run."""
        raise EgressNotAllowedError(EGRESS_NOT_ALLOWED)

    async def aclose(self) -> None:
        """Close the stateless deny transport."""


class _PinnedEgressNetworkBackend(httpcore.AsyncNetworkBackend):
    """Open asynchronous TCP connections only to prevalidated IP addresses."""

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
        self._backend = AutoBackend()

    async def _connect_validated_ip_address(
        self,
        address: str,
        port: int,
        timeout: float | None,
        local_address: str | None,
        socket_options,
    ):
        """Connect to one defensively revalidated pinned IP address."""
        pinned_address = _validate_global_address(
            address, self._policy, hostname=self._hostname
        )
        return await self._backend.connect_tcp(
            pinned_address,
            port,
            timeout=timeout,
            local_address=local_address,
            socket_options=socket_options,
        )

    def _verify_host_port(self, host: str | bytes, port: int) -> None:
        """Reject any authority change after URL validation."""
        host_text = host.decode("ascii") if isinstance(host, bytes) else str(host)
        normalized_host = host_text.lower().rstrip(".")
        if normalized_host != self._hostname or int(port) != self._port:
            raise OSError("egress URL host changed after validation")

    async def _cancel_and_wait_tasks(self, tasks: set) -> None:
        """Cancel and await every losing connection attempt."""
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    async def connect_tcp(
        self,
        host: str | bytes,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options=None,
    ):
        """Race pinned addresses gradually within one connection-timeout budget."""
        self._verify_host_port(host, port)
        loop = asyncio.get_running_loop()
        deadline = None if timeout is None else loop.time() + max(timeout, 0.0)
        address_iterator = iter(self._addresses)
        tasks: set[asyncio.Task] = set()
        last_error: Exception | None = None
        more_addresses = True
        next_attempt_at = loop.time()

        def start_next_attempt() -> bool:
            nonlocal more_addresses, next_attempt_at
            try:
                address = next(address_iterator)
            except StopIteration:
                more_addresses = False
                return False
            remaining_timeout = None
            if deadline is not None:
                remaining_timeout = max(0.0, deadline - loop.time())
            tasks.add(
                asyncio.create_task(
                    self._connect_validated_ip_address(
                        address,
                        port,
                        timeout=remaining_timeout,
                        local_address=local_address,
                        socket_options=socket_options,
                    )
                )
            )
            next_attempt_at = loop.time() + _CONNECTION_ATTEMPT_DELAY_SECONDS
            return True

        start_next_attempt()
        try:
            while tasks:
                wait_timeout = None
                if more_addresses:
                    wait_timeout = max(0.0, next_attempt_at - loop.time())
                    if deadline is not None:
                        remaining_budget = max(0.0, deadline - loop.time())
                        if remaining_budget <= 0:
                            more_addresses = False
                            wait_timeout = None
                        else:
                            wait_timeout = min(wait_timeout, remaining_budget)
                done, pending = await asyncio.wait(
                    tasks,
                    timeout=wait_timeout,
                    return_when=asyncio.FIRST_COMPLETED,
                )
                tasks.clear()
                tasks.update(pending)
                if not done:
                    if more_addresses:
                        start_next_attempt()
                    continue
                successful_stream = None
                for task in done:
                    try:
                        stream = task.result()
                    except Exception as exc:  # noqa: BLE001  # pragma: no cover
                        last_error = exc
                        continue
                    if successful_stream is None:
                        successful_stream = stream
                    else:
                        await stream.aclose()
                if successful_stream is not None:
                    return successful_stream
                if more_addresses and (not tasks or loop.time() >= next_attempt_at):
                    if deadline is None or loop.time() < deadline:
                        start_next_attempt()
                    else:
                        more_addresses = False
        finally:
            await self._cancel_and_wait_tasks(tasks)
        if last_error is not None:
            raise last_error
        raise OSError(EGRESS_NOT_ALLOWED)

    async def connect_unix_socket(
        self,
        path: str,
        timeout: float | None = None,
        socket_options=None,
    ):
        """Refuse Unix sockets because they bypass hostname policy enforcement."""
        raise OSError("egress URL must not use Unix sockets")

    async def sleep(self, seconds: float) -> None:
        """Delegate cooperative sleeping to the selected async backend."""
        await self._backend.sleep(seconds)


class _PinnedEgressAsyncTransport(httpx.AsyncBaseTransport):
    """Asynchronous HTTPX transport pinned to one validated URL authority."""

    _policy = EgressPolicy(allowed_hosts=frozenset())

    def __init__(
        self,
        validated: ValidatedEgressURL,
        policy: EgressPolicy,
        *,
        tls_configuration: TLSConfiguration | None = None,
    ) -> None:
        """Revalidate state and build a pinned pool with one fresh TLS context."""
        self._validated = _revalidate_pinned_egress_url(validated, policy)
        self._policy = policy
        ssl_context = create_egress_ssl_context(tls_configuration)
        self._pool = httpcore.AsyncConnectionPool(
            ssl_context=ssl_context,
            max_connections=DEFAULT_LIMITS.max_connections,
            max_keepalive_connections=DEFAULT_LIMITS.max_keepalive_connections,
            keepalive_expiry=DEFAULT_LIMITS.keepalive_expiry,
            http1=True,
            http2=False,
            network_backend=_PinnedEgressNetworkBackend(
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

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        """Send one target-, metadata-, and framing-exact bounded request."""
        self._verify_request_target(request)
        parsed_url = urlsplit(self._validated.normalized_url)
        try:
            safe_target = _enforce_request_target_limit(
                request.url.raw_path,
                self._policy.max_request_target_bytes,
            )
            safe_extensions = _bind_bounded_request_timeouts(
                _bind_validated_tls_server_name(
                    request.extensions, self._validated.hostname
                ),
                self._policy.request_timeout_policy,
            )
            safe_headers = _force_identity_accept_encoding(
                _build_safe_request_headers(
                    request.headers.raw, parsed_url.netloc.encode("ascii")
                )
            )
            _enforce_request_header_limits(
                safe_headers,
                self._policy.max_request_header_fields,
                self._policy.max_request_header_bytes,
            )
            declared_request_bytes = _enforce_declared_request_size(
                safe_headers, self._policy.max_request_bytes
            )
        except EgressNotAllowedError:
            try:
                await request.stream.aclose()
            except Exception:  # noqa: BLE001, S110
                pass
            raise EgressNotAllowedError(EGRESS_NOT_ALLOWED) from None

        req = httpcore.Request(
            method=request.method,
            url=httpcore.URL(
                scheme=parsed_url.scheme.encode("ascii"),
                host=self._validated.hostname.encode("ascii"),
                port=self._validated.port,
                target=safe_target,
            ),
            headers=safe_headers,
            content=_BoundedAsyncRequestStream(
                request.stream,
                self._policy.max_request_bytes,
                declared_request_bytes,
            ),
            extensions=safe_extensions,
        )
        with map_httpcore_exceptions():
            resp = await self._pool.handle_async_request(req)

        response_denied = False
        try:
            _enforce_response_header_limits(
                resp.headers,
                self._policy.max_response_header_fields,
                self._policy.max_response_header_bytes,
            )
            _enforce_declared_response_size(
                request.method,
                resp.status,
                resp.headers,
                self._policy.max_response_bytes,
            )
        except EgressNotAllowedError:
            response_denied = True
        if response_denied:
            try:
                await resp.stream.aclose()
            except Exception:  # noqa: BLE001, S110
                pass
            raise EgressNotAllowedError(EGRESS_NOT_ALLOWED) from None

        return httpx.Response(
            status_code=resp.status,
            headers=resp.headers,
            stream=_BoundedAsyncResponseStream(
                AsyncResponseStream(resp.stream), self._policy.max_response_bytes
            ),
            extensions=resp.extensions,
        )

    async def aclose(self) -> None:
        """Close the underlying pinned asynchronous connection pool."""
        await self._pool.aclose()


async def build_egress_http_client(
    base_url: str | None,
    *,
    policy: EgressPolicy,
    tls_configuration: TLSConfiguration | None = None,
) -> tuple[str | None, httpx.AsyncClient]:
    """Build a DNS-pinned, fail-closed client for ``base_url``.

    Empty or absent URLs return a deny-all client. Exact outbound targets are
    limited by ``policy.max_request_target_bytes``. Final outbound fields are
    limited by ``policy.max_request_header_fields`` and
    ``policy.max_request_header_bytes``. Request bodies are limited to
    ``policy.max_request_bytes`` and must match a supplied ``Content-Length``
    exactly. Request-phase timeout metadata is capped by
    ``policy.request_timeout_policy``. Response headers are limited by
    ``policy.max_response_header_fields`` and
    ``policy.max_response_header_bytes`` before delivery. Successful response
    bodies are requested with identity coding and limited to
    ``policy.max_response_bytes``.
    """
    validated = await validate_egress_url_details_async(base_url, policy=policy)
    if validated is None:
        return (
            None,
            httpx.AsyncClient(
                follow_redirects=False,
                trust_env=False,
                transport=_DenyAllAsyncTransport(),
            ),
        )
    return (
        validated.normalized_url,
        httpx.AsyncClient(
            follow_redirects=False,
            trust_env=False,
            transport=_PinnedEgressAsyncTransport(
                validated, policy, tls_configuration=tls_configuration
            ),
        ),
    )


def build_pinned_https_async_client(
    validated: ValidatedEgressURL,
    *,
    policy: EgressPolicy,
    tls_configuration: TLSConfiguration | None = None,
) -> httpx.AsyncClient:
    """Build an async client with bounded request, timeout, and response policy."""
    return httpx.AsyncClient(
        follow_redirects=False,
        trust_env=False,
        transport=_PinnedEgressAsyncTransport(
            validated, policy, tls_configuration=tls_configuration
        ),
    )
