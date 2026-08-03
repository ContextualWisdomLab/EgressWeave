"""Regression tests for deterministic IDNA hostname canonicalization."""

import socket

import pytest

from egressweave import EgressNotAllowedError, EgressPolicy
from egressweave import validation as v
from egressweave.policy import _normalize_host

PUBLIC_ADDRESS = "93.184.216.34"


def test_policy_normalizes_unicode_and_alabel_hosts() -> None:
    policy = EgressPolicy.from_hosts(["TÄST.de.", "xn--tst-qla.de"])

    assert policy.allowed_hosts == frozenset({"xn--tst-qla.de"})


def test_policy_normalizes_unicode_dot_separator() -> None:
    policy = EgressPolicy.from_hosts("example。com")

    assert policy.allowed_hosts == frozenset({"example.com"})


@pytest.mark.parametrize(
    "host", ["💩.example", "bad..example", "_service.example", "*"]
)
def test_policy_rejects_invalid_idna_hosts(host: str) -> None:
    with pytest.raises(ValueError, match="valid IDNA name"):
        EgressPolicy.from_hosts(host)


def test_policy_rejects_non_string_hosts() -> None:
    with pytest.raises(ValueError, match="hostnames must be strings"):
        EgressPolicy.from_hosts([123])


def test_ip_literals_are_canonicalized_without_idna() -> None:
    assert _normalize_host("127.0.0.1") == "127.0.0.1"
    assert _normalize_host("0:0:0:0:0:0:0:1") == "::1"


def test_unicode_url_is_normalized_to_alabel(monkeypatch: pytest.MonkeyPatch) -> None:
    policy = EgressPolicy.from_hosts("täst.de")

    monkeypatch.setattr(
        v.socket,
        "getaddrinfo",
        lambda host, port, type=None: [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", (PUBLIC_ADDRESS, port))
        ],
    )

    validated = v.validate_egress_url_details("https://TÄST.de/v1", policy=policy)

    assert validated is not None
    assert validated.normalized_url == "https://xn--tst-qla.de/v1"
    assert validated.hostname == "xn--tst-qla.de"


@pytest.mark.parametrize("url", ["https://💩.example", "https://bad..example"])
def test_invalid_idna_url_fails_with_generic_egress_error(url: str) -> None:
    policy = EgressPolicy.from_hosts("example.com")

    with pytest.raises(EgressNotAllowedError, match="^egress URL is not allowed$"):
        v._normalize_egress_url(url, policy)
