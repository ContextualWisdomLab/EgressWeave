"""DNS-pinned httpx transport for egressweave.

Validation alone is not enough: between the moment a hostname is resolved and
checked and the moment a connection is opened, the DNS answer can change so the
socket lands on a private address the check never saw (CWE-350, DNS rebinding /
a validate-then-connect TOCTOU).

This transport closes that gap. Every outbound connection is pinned to the exact
addresses returned at validation time, each address is re-validated against the
policy immediately before ``connect``, and any host/port that differs from the
validated one is rejected. Redirects are disabled, environment proxies ignored
(``trust_env=False``), and Unix sockets refused.

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
from httpx._config import DEFAULT_LIMITS, create_ssl_context
from httpx._transports.default import AsyncResponseStream, map_httpcore_exceptions

from egressweave.policy import EgressPolicy
from egressweave.request_safety import _bind_validated_tls_server_name
from egressweave.validation import (
    EGRESS_NOT_ALLOWED,
    EgressNotAllowedError,
    ValidatedEgressURL,
    _revalidate_pinned_egress_url,
    _validate_global_address,
    validate_egress_url_details_async,
)


class _DenyAllAsyncTransport(httpx.AsyncBaseTransport):
    """Fail-closed transport used when no outbound authority was validated."""

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        """Reject every request before any network or proxy code can run."""
        raise EgressNotAllowedError(EGRESS_NOT_ALLOWED)

    async def aclose(self) -> None:
        """Close the stateless deny transport."""


class _PinnedEgressNetworkBackend(httpcore.AsyncNetworkBackend):
    def __init__(
        self,
        hostname: str,
        port: int,
        addresses: tuple[str, ...],
        policy: EgressPolicy,
    ) -> None:
        if not addresses:
            raise EgressNotAllowedError(EGRESS_NOT_ALLOWED)
        self._hostname = hostname
        self._port = port
        self._policy = policy
        # Re-validate each address; pass the hostname so allowlisted local
        # container names are accepted under ``allow_local``.
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
        host_text = host.decode("ascii") if isinstance(host, bytes) else str(host)
        normalized_host = host_text.lower().rstrip(".")
        if normalized_host != self._hostname or int(port) != self._port:
            raise OSError("egress URL host changed after validation")

    async def _cancel_and_wait_tasks(self, tasks: set) -> None:
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    async def _wait_for_first_successful_stream(self, tasks: set):
        last_error: Exception | None = None
        while tasks:
            done, tasks_remaining = await asyncio.wait(
                tasks, return_when=asyncio.FIRST_COMPLETED
            )
            tasks.clear()
            tasks.update(tasks_remaining)

            successful_stream = None
            for task in done:
                try:
                    stream = task.result()
                except Exception as exc:  # noqa: BLE001  # pragma: no cover
                    # Backends expose different connection exception classes;
                    # one failed address must not abort the remaining candidates.
                    last_error = exc
                    continue

                if successful_stream is None:
                    successful_stream = stream
                else:
                    await stream.aclose()

            if successful_stream is not None:
                return successful_stream, last_error
        return None, last_error

    async def connect_tcp(
        self,
        host: str | bytes,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options=None,
    ):
        self._verify_host_port(host, port)

        tasks = {
            asyncio.create_task(
                self._connect_validated_ip_address(
                    address,
                    port,
                    timeout=timeout,
                    local_address=local_address,
                    socket_options=socket_options,
                )
            )
            for address in self._addresses
        }

        try:
            (
                successful_stream,
                last_error,
            ) = await self._wait_for_first_successful_stream(tasks)
            if successful_stream is not None:
                return successful_stream
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
        raise OSError("egress URL must not use Unix sockets")

    async def sleep(self, seconds: float) -> None:
        await self._backend.sleep(seconds)


class _PinnedEgressAsyncTransport(httpx.AsyncBaseTransport):
    def __init__(self, validated: ValidatedEgressURL, policy: EgressPolicy) -> None:
        self._validated = _revalidate_pinned_egress_url(validated, policy)
        ssl_context = create_ssl_context(verify=True, trust_env=False)
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

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self._verify_request_target(request)
        parsed_url = urlsplit(self._validated.normalized_url)
        validated_scheme = parsed_url.scheme.encode("ascii")
        validated_host = self._validated.hostname.encode("ascii")
        validated_netloc = parsed_url.netloc.encode("ascii")
        safe_extensions = _bind_validated_tls_server_name(
            request.extensions, self._validated.hostname
        )

        safe_headers = [
            (key, value)
            for key, value in request.headers.raw
            if key.lower() != b"host"
        ]
        safe_headers.append((b"host", validated_netloc))

        req = httpcore.Request(
            method=request.method,
            url=httpcore.URL(
                scheme=validated_scheme,
                host=validated_host,
                port=self._validated.port,
                target=request.url.raw_path,
            ),
            headers=safe_headers,
            content=request.stream,
            extensions=safe_extensions,
        )
        with map_httpcore_exceptions():
            resp = await self._pool.handle_async_request(req)

        return httpx.Response(
            status_code=resp.status,
            headers=resp.headers,
            stream=AsyncResponseStream(resp.stream),
            extensions=resp.extensions,
        )

    async def aclose(self) -> None:
        await self._pool.aclose()


async def build_egress_http_client(
    base_url: str | None, *, policy: EgressPolicy
) -> tuple[str | None, httpx.AsyncClient]:
    """Build a DNS-pinned, fail-closed client for ``base_url``.

    Returns ``(normalized_url, client)``. When ``base_url`` is empty or absent,
    the normalized URL is ``None`` and the returned client rejects every
    request before network I/O. A non-empty URL that violates the policy raises
    :class:`~egressweave.validation.EgressNotAllowedError`.
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
            transport=_PinnedEgressAsyncTransport(validated, policy),
        ),
    )


def build_pinned_https_async_client(
    validated: ValidatedEgressURL, *, policy: EgressPolicy
) -> httpx.AsyncClient:
    """Build a DNS-pinned ``httpx.AsyncClient`` for an already-validated URL.

    The supplied result is revalidated without another DNS lookup, then every
    outbound connection is pinned to its addresses. Any forged policy/URL/host/
    port combination or post-validation host/port change is rejected.
    """
    return httpx.AsyncClient(
        follow_redirects=False,
        trust_env=False,
        transport=_PinnedEgressAsyncTransport(validated, policy),
    )
