"""Regressions for the privacy-minimized decision-evidence authority schema."""

from __future__ import annotations

import re

import egressweave


def _authority_schema() -> dict[str, object]:
    """Return the versioned authority field schema from the public loader."""
    schema = egressweave.get_decision_evidence_json_schema()
    properties = schema["properties"]
    assert isinstance(properties, dict)
    authority = properties["authority"]
    assert isinstance(authority, dict)
    return authority


def test_authority_schema_matches_runtime_canonical_shape() -> None:
    """Accept only bounded lowercase hostname-and-port evidence authorities."""
    authority = _authority_schema()
    pattern = authority["pattern"]

    assert isinstance(pattern, str)
    assert authority["type"] == "string"
    assert authority["minLength"] == 3
    assert authority["maxLength"] == 259

    for value in (
        "api.example.com:443",
        "service-1:80",
        "xn--bcher-kva.example:8443",
        "a:1",
        "api.example.com:65535",
    ):
        assert re.fullmatch(pattern, value) is not None


def test_authority_schema_rejects_non_runtime_and_sensitive_shapes() -> None:
    """Keep URL syntax, credentials, paths, literals, and invalid ports out."""
    pattern = _authority_schema()["pattern"]
    assert isinstance(pattern, str)

    for value in (
        "https://api.example.com:443/private",
        "https://user:secret@example.com/private?token=value",
        "api.example.com/private:443",
        "api.example.com",
        "API.EXAMPLE.COM:443",
        "api.example.com.:443",
        "api..example.com:443",
        "-api.example.com:443",
        "api.example.com-:443",
        "127.0.0.1:443",
        "0x7f000001:443",
        "[2001:db8::1]:443",
        "api.example.com:0",
        "api.example.com:65536",
        "api.example.com:99999",
    ):
        assert re.fullmatch(pattern, value) is None


def test_authority_schema_bounds_hostname_length_independent_of_port_width() -> None:
    """Reject evidence hostnames that exceed the runtime DNS-name ceiling."""
    pattern = _authority_schema()["pattern"]
    assert isinstance(pattern, str)

    label = "a" * 63
    maximum_hostname = f"{label}.{label}.{label}.{'b' * 61}"
    oversized_hostname = f"{label}.{label}.{label}.{'b' * 62}"

    assert len(maximum_hostname) == 253
    assert len(oversized_hostname) == 254
    assert re.fullmatch(pattern, f"{maximum_hostname}:1") is not None
    assert re.fullmatch(pattern, f"{oversized_hostname}:1") is None
