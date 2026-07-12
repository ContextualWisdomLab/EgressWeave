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
