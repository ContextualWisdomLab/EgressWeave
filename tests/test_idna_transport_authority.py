import httpx
import pytest

from egressweave import EgressPolicy, validate_egress_url_details
from egressweave import validation as validation_module
from egressweave.sync_transport import _PinnedEgressTransport
from egressweave.transport import _PinnedEgressAsyncTransport


def _validated_international_host(monkeypatch):
    def fake_getaddrinfo(host, port, type=None):
        assert host == "xn--bcher-kva.example"
        return [(2, 1, 6, "", ("93.184.216.34", port))]

    policy = EgressPolicy.from_hosts("bücher.example")
    monkeypatch.setattr(validation_module.socket, "getaddrinfo", fake_getaddrinfo)
    validated = validate_egress_url_details(
        "https://bücher.example/v1", policy=policy
    )
    assert validated is not None
    return policy, validated


@pytest.mark.parametrize(
    "transport_class",
    [_PinnedEgressTransport, _PinnedEgressAsyncTransport],
    ids=["sync", "async"],
)
def test_transport_matches_unicode_request_host_to_validated_alabel(
    monkeypatch, transport_class
):
    policy, validated = _validated_international_host(monkeypatch)
    transport = object.__new__(transport_class)
    transport._validated = validated
    transport._policy = policy

    transport._verify_request_target(
        httpx.Request("GET", "https://bücher.example/v1/models")
    )
