import pytest

from egressweave import (
    EgressNotAllowedError,
    EgressPolicy,
    validate_egress_url,
    validate_egress_url_details,
)
from egressweave import validation as v

POLICY = EgressPolicy.from_hosts("api.openai.com")


def test_empty_or_absent_returns_none():
    assert validate_egress_url(None, policy=POLICY) is None
    assert validate_egress_url("   ", policy=POLICY) is None


@pytest.mark.parametrize(
    "url",
    [
        "https://evil.com/v1",  # host not allowlisted
        "http://api.openai.com/v1",  # plaintext http to a remote host
        "ftp://api.openai.com/v1",  # non-http(s) scheme
        "https://user:pass@api.openai.com/v1",  # embedded credentials
        "https://api.openai.com/v1?token=1",  # query string
        "https://api.openai.com/v1#frag",  # fragment
        "https://api.openai.com\\@evil.com/v1",  # backslash smuggling
        "https://api.openai.com\t/v1",  # control character
        "https://93.184.216.34/v1",  # IP literal, not allowlisted
    ],
)
def test_normalize_rejects_bad_urls(url):
    with pytest.raises(EgressNotAllowedError):
        v._normalize_egress_url(url, POLICY)


def test_normalize_accepts_and_canonicalizes_allowlisted():
    normalized, hostname, port = v._normalize_egress_url(
        "https://API.OpenAI.com/v1/", POLICY
    )
    assert hostname == "api.openai.com"
    assert port == 443
    assert normalized == "https://api.openai.com/v1/"


def test_normalize_maps_unicode_hostname_to_ascii_alabel():
    policy = EgressPolicy.from_hosts("BÜCHER.example")
    normalized, hostname, port = v._normalize_egress_url(
        "https://bücher.example/v1", policy
    )
    assert hostname == "xn--bcher-kva.example"
    assert port == 443
    assert normalized == "https://xn--bcher-kva.example/v1"


@pytest.mark.parametrize(
    "address",
    [
        "127.0.0.1",  # loopback
        "10.0.0.1",  # RFC 1918 private
        "192.168.1.1",  # RFC 1918 private
        "169.254.1.1",  # link-local
        "::1",  # IPv6 loopback
        "0.0.0.0",  # unspecified
        "224.0.0.1",  # multicast
        "240.0.0.1",  # reserved
    ],
)
def test_validate_global_address_rejects_non_global(address):
    with pytest.raises(EgressNotAllowedError):
        v._validate_global_address(address, POLICY)


def test_validate_global_address_accepts_public():
    assert v._validate_global_address("93.184.216.34", POLICY) == "93.184.216.34"


def test_allow_local_accepts_loopback_for_local_hostname():
    policy = EgressPolicy.from_hosts("ollama", allow_local=True)
    assert (
        v._validate_global_address("127.0.0.1", policy, hostname="localhost")
        == "127.0.0.1"
    )


def test_allow_local_accepts_allowlisted_container_private_ip():
    policy = EgressPolicy.from_hosts("ollama", allow_local=True)
    # A private IP is accepted only because the original hostname is an
    # allowlisted single-label local host (the Docker-container case).
    assert (
        v._validate_global_address("172.17.0.2", policy, hostname="ollama")
        == "172.17.0.2"
    )


def test_allow_local_still_rejects_private_ip_for_unlisted_host():
    policy = EgressPolicy.from_hosts("ollama", allow_local=True)
    with pytest.raises(EgressNotAllowedError):
        v._validate_global_address("172.17.0.2", policy, hostname="not-listed")


def test_full_validate_resolves_and_pins_public_address(monkeypatch):
    def fake_getaddrinfo(host, port, type=None):
        return [(2, 1, 6, "", ("93.184.216.34", port))]

    monkeypatch.setattr(v.socket, "getaddrinfo", fake_getaddrinfo)
    details = validate_egress_url_details("https://api.openai.com/v1", policy=POLICY)
    assert details is not None
    assert details.hostname == "api.openai.com"
    assert details.port == 443
    assert details.addresses == ("93.184.216.34",)


def test_full_validate_resolves_the_canonical_alabel(monkeypatch):
    resolved_hosts = []

    def fake_getaddrinfo(host, port, type=None):
        resolved_hosts.append(host)
        return [(2, 1, 6, "", ("93.184.216.34", port))]

    policy = EgressPolicy.from_hosts("BÜCHER.example")
    monkeypatch.setattr(v.socket, "getaddrinfo", fake_getaddrinfo)
    details = validate_egress_url_details("https://bücher.example/v1", policy=policy)

    assert details is not None
    assert details.normalized_url == "https://xn--bcher-kva.example/v1"
    assert details.hostname == "xn--bcher-kva.example"
    assert resolved_hosts == ["xn--bcher-kva.example"]


def test_full_validate_rejects_allowlisted_host_resolving_to_private(monkeypatch):
    # DNS-rebinding / SSRF-via-DNS: the host is allowlisted, but it resolves to
    # a private address, so validation must reject it before any connection.
    def fake_getaddrinfo(host, port, type=None):
        return [(2, 1, 6, "", ("10.0.0.5", port))]

    monkeypatch.setattr(v.socket, "getaddrinfo", fake_getaddrinfo)
    with pytest.raises(EgressNotAllowedError):
        validate_egress_url_details("https://api.openai.com/v1", policy=POLICY)


async def test_async_validate_matches_sync(monkeypatch):
    def fake_getaddrinfo(host, port, type=None):
        return [(2, 1, 6, "", ("93.184.216.34", port))]

    monkeypatch.setattr(v.socket, "getaddrinfo", fake_getaddrinfo)
    from egressweave import validate_egress_url_async

    result = await validate_egress_url_async(
        "https://api.openai.com/v1", policy=POLICY
    )
    assert result == "https://api.openai.com/v1"
