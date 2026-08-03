import math

import pytest

from egressweave import EgressPolicy


def test_from_hosts_string_normalizes():
    policy = EgressPolicy.from_hosts("API.OpenAI.com, api.anthropic.com. , ")
    assert policy.allowed_hosts == frozenset({"api.openai.com", "api.anthropic.com"})
    assert policy.allow_local is False


def test_from_hosts_iterable():
    policy = EgressPolicy.from_hosts(["Ollama"], allow_local=True)
    assert policy.allowed_hosts == frozenset({"ollama"})
    assert policy.allow_local is True


def test_direct_construction_normalizes():
    policy = EgressPolicy(allowed_hosts=frozenset({"API.Example.COM."}))
    assert policy.allowed_hosts == frozenset({"api.example.com"})


def test_is_allowlisted_local_host_requires_allow_local_and_single_label():
    allowed = EgressPolicy.from_hosts("ollama", allow_local=True)
    assert allowed.is_allowlisted_local_host("ollama") is True
    # A dotted host is never a single-label local host.
    assert allowed.is_allowlisted_local_host("ollama.example.com") is False
    # allow_local disabled → never a local host.
    disabled = EgressPolicy.from_hosts("ollama", allow_local=False)
    assert disabled.is_allowlisted_local_host("ollama") is False
    # Not in the allowlist → not local.
    assert allowed.is_allowlisted_local_host("other") is False


def test_dns_timeout_is_normalized_to_float():
    policy = EgressPolicy.from_hosts("api.openai.com", dns_timeout_seconds=2)

    assert policy.dns_timeout_seconds == 2.0
    assert isinstance(policy.dns_timeout_seconds, float)


@pytest.mark.parametrize(
    "timeout",
    [0, -1, math.inf, -math.inf, math.nan, True, "5", 10**1000],
    ids=[
        "zero",
        "negative",
        "positive-infinity",
        "negative-infinity",
        "nan",
        "bool",
        "str",
        "overflowing-int",
    ],
)
def test_invalid_dns_timeouts_are_rejected(timeout):
    with pytest.raises(ValueError, match="finite positive number"):
        EgressPolicy.from_hosts("api.openai.com", dns_timeout_seconds=timeout)


def test_default_ports_are_standard_http_and_https() -> None:
    policy = EgressPolicy.from_hosts("api.openai.com")

    assert policy.allowed_ports == frozenset({80, 443})
    assert policy.is_port_allowed(443) is True
    assert policy.is_port_allowed(8443) is False


def test_custom_ports_are_normalized_and_deduplicated() -> None:
    policy = EgressPolicy.from_hosts(
        "api.openai.com", allowed_ports=[443, 8443, 8443]
    )

    assert policy.allowed_ports == frozenset({443, 8443})


@pytest.mark.parametrize(
    "ports",
    [(0,), (65536,), (-1,), (True,), ("443",)],
    ids=["zero", "too-large", "negative", "bool", "str"],
)
def test_invalid_allowed_ports_are_rejected(ports) -> None:
    with pytest.raises(ValueError, match="integers from 1 through 65535"):
        EgressPolicy.from_hosts("api.openai.com", allowed_ports=ports)
