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


@pytest.mark.parametrize("invalid_allow_local", ["false", "true", 0, 1, None])
def test_allow_local_requires_an_explicit_boolean(invalid_allow_local):
    with pytest.raises(TypeError, match="allow_local must be a boolean"):
        EgressPolicy.from_hosts("ollama", allow_local=invalid_allow_local)


@pytest.mark.parametrize(
    "invalid_host",
    [
        "*.example.com",
        "https://api.example.com",
        "api.example.com:443",
        "user@api.example.com",
        "api.example.com/path",
        "api.example.com?debug=true",
        "api.example.com#fragment",
        "api\\example.com",
        "api example.com",
        "127.0.0.1",
        "2130706433",
        "0x7f000001",
        "::1",
    ],
)
def test_invalid_allowed_host_configuration_fails_fast(invalid_host):
    with pytest.raises(ValueError, match="exact hostnames"):
        EgressPolicy.from_hosts(invalid_host)


def test_non_string_allowed_host_configuration_fails_fast():
    with pytest.raises(TypeError, match="exact hostname strings"):
        EgressPolicy(allowed_hosts=frozenset({"api.example.com", 443}))


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
