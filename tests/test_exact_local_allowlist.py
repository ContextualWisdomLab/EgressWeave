"""Regression coverage for exact local-development hostname authorization."""

import pytest

from egressweave import (
    EgressNotAllowedError,
    EgressPolicy,
    validate_egress_url_details,
    validate_egress_url_details_async,
)
from egressweave import validation as v

LOCAL_PORT = 11434


def _loopback_getaddrinfo(host, port, type=None):
    return [(2, 1, 6, "", ("127.0.0.1", port))]


def test_localhost_requires_exact_allowlisting_before_dns(monkeypatch):
    resolution_attempted = False

    def unexpected_getaddrinfo(host, port, type=None):
        nonlocal resolution_attempted
        resolution_attempted = True
        return _loopback_getaddrinfo(host, port, type=type)

    policy = EgressPolicy.from_hosts(
        "ollama",
        allow_local=True,
        allowed_ports={LOCAL_PORT},
    )
    monkeypatch.setattr(v.socket, "getaddrinfo", unexpected_getaddrinfo)

    with pytest.raises(EgressNotAllowedError):
        validate_egress_url_details(
            f"http://localhost:{LOCAL_PORT}",
            policy=policy,
        )

    assert resolution_attempted is False


async def test_async_localhost_requires_exact_allowlisting_before_dns(monkeypatch):
    resolution_attempted = False

    def unexpected_getaddrinfo(host, port, type=None):
        nonlocal resolution_attempted
        resolution_attempted = True
        return _loopback_getaddrinfo(host, port, type=type)

    policy = EgressPolicy.from_hosts(
        "ollama",
        allow_local=True,
        allowed_ports={LOCAL_PORT},
    )
    monkeypatch.setattr(v.socket, "getaddrinfo", unexpected_getaddrinfo)

    with pytest.raises(EgressNotAllowedError):
        await validate_egress_url_details_async(
            f"http://localhost:{LOCAL_PORT}",
            policy=policy,
        )

    assert resolution_attempted is False


@pytest.mark.parametrize(
    "url",
    [
        f"http://127.0.0.1:{LOCAL_PORT}",
        f"http://[::1]:{LOCAL_PORT}",
        f"https://127.0.0.1:{LOCAL_PORT}",
        f"https://[::1]:{LOCAL_PORT}",
    ],
)
def test_local_ip_literal_urls_remain_forbidden(url, monkeypatch):
    resolution_attempted = False

    def unexpected_getaddrinfo(host, port, type=None):
        nonlocal resolution_attempted
        resolution_attempted = True
        return _loopback_getaddrinfo(host, port, type=type)

    policy = EgressPolicy.from_hosts(
        "localhost",
        allow_local=True,
        allowed_ports={LOCAL_PORT},
    )
    monkeypatch.setattr(v.socket, "getaddrinfo", unexpected_getaddrinfo)

    with pytest.raises(EgressNotAllowedError):
        validate_egress_url_details(url, policy=policy)

    assert resolution_attempted is False


@pytest.mark.parametrize("hostname", ["localhost", "localhost.localdomain"])
def test_explicitly_allowlisted_local_name_resolves_only_to_loopback(
    hostname,
    monkeypatch,
):
    monkeypatch.setattr(v.socket, "getaddrinfo", _loopback_getaddrinfo)
    policy = EgressPolicy.from_hosts(
        hostname,
        allow_local=True,
        allowed_ports={LOCAL_PORT},
    )

    validated = validate_egress_url_details(
        f"http://{hostname}:{LOCAL_PORT}",
        policy=policy,
    )

    assert validated is not None
    assert validated.hostname == hostname
    assert validated.addresses == ("127.0.0.1",)
