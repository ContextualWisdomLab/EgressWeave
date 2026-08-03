import httpcore
import httpx
import pytest

from egressweave import (
    EgressNotAllowedError,
    EgressPolicy,
    build_egress_sync_client,
    build_pinned_https_client,
    validate_egress_url_details,
)
from egressweave import validation as v
from egressweave.sync_transport import (
    _PinnedEgressSyncNetworkBackend,
    _PinnedEgressTransport,
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
    def handle_request(self, request):
        pytest.fail("request target drift reached the connection pool")


class _RecordingPool:
    def __init__(self):
        self.request = None
        self.closed = False

    def handle_request(self, request):
        self.request = request
        return httpcore.Response(204, headers=[], content=b"")

    def close(self):
        self.closed = True


def test_sync_backend_rejects_empty_addresses():
    with pytest.raises(EgressNotAllowedError):
        _PinnedEgressSyncNetworkBackend("api.openai.com", 443, (), POLICY)


def test_sync_backend_revalidates_pinned_addresses_at_construction():
    with pytest.raises(EgressNotAllowedError):
        _PinnedEgressSyncNetworkBackend(
            "api.openai.com", 443, ("10.0.0.1",), POLICY
        )


def test_sync_backend_rejects_post_validation_authority_change():
    backend = _PinnedEgressSyncNetworkBackend(
        "api.openai.com", 443, ("93.184.216.34",), POLICY
    )

    with pytest.raises(OSError):
        backend._verify_host_port("evil.example", 443)
    with pytest.raises(OSError):
        backend._verify_host_port("api.openai.com", 8443)
    backend._verify_host_port(b"api.openai.com.", 443)


def test_sync_backend_tries_each_pinned_address_with_one_timeout_budget():
    backend = _PinnedEgressSyncNetworkBackend(
        "api.openai.com",
        443,
        ("93.184.216.34", "93.184.216.35"),
        POLICY,
    )
    connected_stream = object()

    class _FallbackBackend:
        def __init__(self):
            self.calls = []

        def connect_tcp(self, host, port, **kwargs):
            self.calls.append((host, port, kwargs))
            if len(self.calls) == 1:
                raise OSError("first address unavailable")
            return connected_stream

    fallback = _FallbackBackend()
    backend._backend = fallback

    assert backend.connect_tcp("api.openai.com", 443, timeout=3.0) is connected_stream
    assert [call[0] for call in fallback.calls] == [
        "93.184.216.34",
        "93.184.216.35",
    ]
    assert all(0.0 <= call[2]["timeout"] <= 3.0 for call in fallback.calls)


def test_sync_backend_refuses_unix_socket():
    backend = _PinnedEgressSyncNetworkBackend(
        "api.openai.com", 443, ("93.184.216.34",), POLICY
    )

    with pytest.raises(OSError):
        backend.connect_unix_socket("/tmp/anything.sock")


@pytest.mark.parametrize(
    "request_url",
    [
        "https://api.openai.com/v1/models",
        "HTTPS://API.OPENAI.COM/v1/models?after=cursor",
        "https://api.openai.com.:443/v1/models",
    ],
    ids=["path-and-query", "canonical-case", "trailing-dot-and-default-port"],
)
def test_sync_transport_accepts_canonical_request_target(
    monkeypatch, request_url
):
    transport = object.__new__(_PinnedEgressTransport)
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
def test_sync_transport_rejects_request_target_drift(monkeypatch, request_url):
    transport = object.__new__(_PinnedEgressTransport)
    transport._validated = _validated_result(monkeypatch)
    transport._pool = _UnexpectedPool()

    with pytest.raises(EgressNotAllowedError, match="^egress URL is not allowed$"):
        transport.handle_request(httpx.Request("GET", request_url))


def test_sync_transport_restores_validated_authority(monkeypatch):
    transport = object.__new__(_PinnedEgressTransport)
    transport._validated = _validated_result(monkeypatch)
    pool = _RecordingPool()
    transport._pool = pool

    response = transport.handle_request(
        httpx.Request(
            "GET",
            "https://api.openai.com/v1/models?after=cursor",
            headers={"Host": "evil.example"},
        )
    )

    assert response.status_code == 204
    assert pool.request.url.host == b"api.openai.com"
    assert pool.request.url.target == b"/v1/models?after=cursor"
    assert dict(pool.request.headers)[b"host"] == b"api.openai.com"


def test_sync_transport_close_closes_pool(monkeypatch):
    transport = object.__new__(_PinnedEgressTransport)
    transport._validated = _validated_result(monkeypatch)
    pool = _RecordingPool()
    transport._pool = pool

    transport.close()

    assert pool.closed is True


def test_build_pinned_sync_client_constructs(monkeypatch):
    validated = _validated_result(monkeypatch)

    with build_pinned_https_client(validated, policy=POLICY) as client:
        assert isinstance(client, httpx.Client)
        assert client.follow_redirects is False
        assert client.trust_env is False


def test_build_sync_client_without_base_url_fails_closed():
    normalized_url, client = build_egress_sync_client(None, policy=POLICY)

    try:
        assert normalized_url is None
        assert client.follow_redirects is False
        assert client.trust_env is False
        with pytest.raises(
            EgressNotAllowedError, match="^egress URL is not allowed$"
        ):
            client.get("https://api.openai.com/v1/models")
    finally:
        client.close()
