import httpx
import pytest

from egressweave import (
    EgressNotAllowedError,
    EgressPolicy,
    build_egress_http_client,
    build_pinned_https_async_client,
    validate_egress_url_details,
)
from egressweave import validation as v
from egressweave.transport import (
    _PinnedEgressAsyncTransport,
    _PinnedEgressNetworkBackend,
)

POLICY = EgressPolicy.from_hosts("api.openai.com")


def _validated_result(monkeypatch):
    def fake_getaddrinfo(host, port, type=None):
        return [(2, 1, 6, "", ("93.184.216.34", port))]

    monkeypatch.setattr(v.socket, "getaddrinfo", fake_getaddrinfo)
    validated = validate_egress_url_details(
        "https://api.openai.com", policy=POLICY
    )
    assert validated is not None
    return validated


class _UnexpectedPool:
    async def handle_async_request(self, request):
        pytest.fail("request target drift reached the connection pool")


def test_backend_rejects_empty_addresses():
    with pytest.raises(EgressNotAllowedError):
        _PinnedEgressNetworkBackend("api.openai.com", 443, (), POLICY)


def test_backend_revalidates_pinned_addresses_at_construction():
    # A private address slipped into the pinned set is rejected up front.
    with pytest.raises(EgressNotAllowedError):
        _PinnedEgressNetworkBackend("api.openai.com", 443, ("10.0.0.1",), POLICY)


def test_verify_host_port_rejects_post_validation_change():
    backend = _PinnedEgressNetworkBackend(
        "api.openai.com", 443, ("93.184.216.34",), POLICY
    )
    with pytest.raises(OSError):
        backend._verify_host_port("evil.com", 443)
    with pytest.raises(OSError):
        backend._verify_host_port("api.openai.com", 8443)
    # The validated host/port is accepted (bytes and trailing dot tolerated).
    backend._verify_host_port(b"api.openai.com.", 443)


async def test_connect_unix_socket_is_refused():
    backend = _PinnedEgressNetworkBackend(
        "api.openai.com", 443, ("93.184.216.34",), POLICY
    )
    with pytest.raises(OSError):
        await backend.connect_unix_socket("/tmp/anything.sock")


@pytest.mark.parametrize(
    "request_url",
    [
        "https://api.openai.com/v1/models",
        "HTTPS://API.OPENAI.COM/v1/models?after=cursor",
        "https://api.openai.com.:443/v1/models",
    ],
    ids=["path-and-query", "canonical-case", "trailing-dot-and-default-port"],
)
def test_transport_accepts_canonical_request_target(monkeypatch, request_url):
    transport = object.__new__(_PinnedEgressAsyncTransport)
    transport._validated = _validated_result(monkeypatch)

    transport._verify_request_target(httpx.Request("GET", request_url))


@pytest.mark.parametrize(
    "request_url",
    [
        "https://evil.example/v1",
        "http://api.openai.com/v1",
        "https://api.openai.com:8443/v1",
        "https://user:pass@api.openai.com/v1",
        "/v1",
        "ftp://api.openai.com/v1",
    ],
    ids=["host", "scheme", "port", "userinfo", "relative", "unsupported-scheme"],
)
async def test_transport_rejects_request_target_drift(monkeypatch, request_url):
    transport = object.__new__(_PinnedEgressAsyncTransport)
    transport._validated = _validated_result(monkeypatch)
    transport._pool = _UnexpectedPool()

    with pytest.raises(EgressNotAllowedError, match="^egress URL is not allowed$"):
        await transport.handle_async_request(httpx.Request("GET", request_url))


async def test_build_pinned_client_constructs(monkeypatch):
    validated = _validated_result(monkeypatch)
    async with build_pinned_https_async_client(validated, policy=POLICY) as client:
        assert client is not None


async def test_build_async_client_without_base_url_fails_closed():
    normalized_url, client = await build_egress_http_client(None, policy=POLICY)

    try:
        assert normalized_url is None
        assert client.follow_redirects is False
        assert client.trust_env is False
        with pytest.raises(
            EgressNotAllowedError, match="^egress URL is not allowed$"
        ):
            await client.get("https://api.openai.com/v1/models")
    finally:
        await client.aclose()
