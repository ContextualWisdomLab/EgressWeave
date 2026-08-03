"""Regression tests for exact TCP destination-port policy."""

import pytest

from egressweave import EgressNotAllowedError, EgressPolicy
from egressweave import validation as v


@pytest.mark.parametrize(
    "url",
    ["https://api.openai.com:8443/v1", "https://api.openai.com:4443/v1"],
)
def test_default_policy_rejects_nonstandard_remote_ports(url: str) -> None:
    policy = EgressPolicy.from_hosts("api.openai.com")

    with pytest.raises(EgressNotAllowedError, match="^egress URL is not allowed$"):
        v._normalize_egress_url(url, policy)


def test_explicit_remote_port_is_allowed() -> None:
    policy = EgressPolicy.from_hosts("api.openai.com", allowed_ports=(8443,))

    normalized, hostname, port = v._normalize_egress_url(
        "https://API.OpenAI.com:8443/v1", policy
    )

    assert normalized == "https://api.openai.com:8443/v1"
    assert hostname == "api.openai.com"
    assert port == 8443


def test_explicit_local_container_port_is_allowed() -> None:
    policy = EgressPolicy.from_hosts(
        "ollama", allow_local=True, allowed_ports=(11434,)
    )

    normalized, hostname, port = v._normalize_egress_url(
        "http://ollama:11434/api", policy
    )

    assert normalized == "http://ollama:11434/api"
    assert hostname == "ollama"
    assert port == 11434


def test_local_container_port_must_still_be_allowlisted() -> None:
    policy = EgressPolicy.from_hosts("ollama", allow_local=True)

    with pytest.raises(EgressNotAllowedError, match="^egress URL is not allowed$"):
        v._normalize_egress_url("http://ollama:11434/api", policy)
