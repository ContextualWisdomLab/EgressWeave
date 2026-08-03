import pytest

from egressweave import (
    EgressNotAllowedError,
    EgressPolicy,
    validate_egress_url_async,
    validate_egress_url_details,
)
from egressweave import validation as v


def test_default_port_policy_authorizes_only_standard_https():
    policy = EgressPolicy.from_hosts("api.example.com")

    assert policy.allowed_ports == frozenset({443})
    assert policy.allows_port(443) is True
    assert policy.allows_port(80) is False
    assert policy.allows_port(True) is False


def test_port_policy_normalizes_environment_and_iterable_inputs():
    from_environment = EgressPolicy.from_hosts(
        "api.example.com", allowed_ports="443, 8443, "
    )
    from_iterable = EgressPolicy.from_hosts(
        "api.example.com", allowed_ports=[443, "8443"]
    )

    assert from_environment.allowed_ports == frozenset({443, 8443})
    assert from_iterable.allowed_ports == frozenset({443, 8443})


@pytest.mark.parametrize("invalid_port", [0, -1, 65536, "443.0", "port"])
def test_invalid_port_configuration_fails_fast_with_value_error(invalid_port):
    with pytest.raises(ValueError, match="allowed_ports"):
        EgressPolicy.from_hosts("api.example.com", allowed_ports=[invalid_port])


@pytest.mark.parametrize("invalid_port", [True, 443.0, None])
def test_invalid_port_configuration_fails_fast_with_type_error(invalid_port):
    with pytest.raises(TypeError, match="allowed_ports"):
        EgressPolicy.from_hosts("api.example.com", allowed_ports=[invalid_port])


def test_nonstandard_port_is_rejected_before_dns_resolution(monkeypatch):
    policy = EgressPolicy.from_hosts("api.example.com")

    def unexpected_dns(*args, **kwargs):  # pragma: no cover - failure sentinel
        raise AssertionError("port rejection must happen before DNS resolution")

    monkeypatch.setattr(v.socket, "getaddrinfo", unexpected_dns)

    with pytest.raises(EgressNotAllowedError, match="egress URL is not allowed"):
        validate_egress_url_details("https://api.example.com:8443/v1", policy=policy)


def test_explicit_port_opt_in_is_normalized_and_resolved(monkeypatch):
    policy = EgressPolicy.from_hosts("api.example.com", allowed_ports={8443})

    def fake_getaddrinfo(host, port, type=None):
        assert host == "api.example.com"
        assert port == 8443
        return [(2, 1, 6, "", ("93.184.216.34", port))]

    monkeypatch.setattr(v.socket, "getaddrinfo", fake_getaddrinfo)

    details = validate_egress_url_details(
        "https://API.Example.com:08443/v1", policy=policy
    )

    assert details is not None
    assert details.normalized_url == "https://api.example.com:8443/v1"
    assert details.port == 8443
    assert details.addresses == ("93.184.216.34",)


def test_explicit_zero_port_is_not_silently_replaced_by_default():
    policy = EgressPolicy.from_hosts("api.example.com")

    with pytest.raises(EgressNotAllowedError, match="egress URL is not allowed"):
        v._normalize_egress_url("https://api.example.com:0/v1", policy)


async def test_async_validation_enforces_the_same_port_policy(monkeypatch):
    allowed = EgressPolicy.from_hosts("api.example.com", allowed_ports={9443})
    denied = EgressPolicy.from_hosts("api.example.com")

    def fake_getaddrinfo(host, port, type=None):
        return [(2, 1, 6, "", ("93.184.216.34", port))]

    monkeypatch.setattr(v.socket, "getaddrinfo", fake_getaddrinfo)

    assert (
        await validate_egress_url_async(
            "https://api.example.com:9443/v1", policy=allowed
        )
        == "https://api.example.com:9443/v1"
    )
    with pytest.raises(EgressNotAllowedError, match="egress URL is not allowed"):
        await validate_egress_url_async(
            "https://api.example.com:9443/v1", policy=denied
        )


def test_local_development_ports_require_explicit_opt_in():
    default_policy = EgressPolicy.from_hosts("ollama", allow_local=True)
    local_policy = EgressPolicy.from_hosts(
        "ollama", allow_local=True, allowed_ports={11434}
    )

    with pytest.raises(EgressNotAllowedError):
        v._normalize_egress_url("http://ollama:11434", default_policy)

    normalized, hostname, port = v._normalize_egress_url(
        "http://ollama:11434", local_policy
    )
    assert normalized == "http://ollama:11434"
    assert hostname == "ollama"
    assert port == 11434
