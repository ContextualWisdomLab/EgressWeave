import pytest

from egressweave import (
    EgressNotAllowedError,
    EgressPolicy,
    ValidatedEgressURL,
    build_pinned_https_async_client,
)
from egressweave.transport import _PinnedEgressNetworkBackend

POLICY = EgressPolicy.from_hosts("api.openai.com")


def test_backend_rejects_empty_addresses():
    with pytest.raises(EgressNotAllowedError):
        _PinnedEgressNetworkBackend("api.openai.com", 443, (), POLICY)


def test_backend_revalidates_pinned_addresses_at_construction():
    # A private address slipped into the pinned set is rejected up front.
    with pytest.raises(EgressNotAllowedError):
        _PinnedEgressNetworkBackend("api.openai.com", 443, ("10.0.0.1",), POLICY)


def test_verify_host_port_rejects_post_validation_change():
    backend = _PinnedEgressNetworkBackend(
        "api.openai.com", 443, ("93.184.216.34",), POLICY
    )
    with pytest.raises(OSError):
        backend._verify_host_port("evil.com", 443)
    with pytest.raises(OSError):
        backend._verify_host_port("api.openai.com", 8443)
    # The validated host/port is accepted (bytes and trailing dot tolerated).
    backend._verify_host_port(b"api.openai.com.", 443)


async def test_connect_unix_socket_is_refused():
    backend = _PinnedEgressNetworkBackend(
        "api.openai.com", 443, ("93.184.216.34",), POLICY
    )
    with pytest.raises(OSError):
        await backend.connect_unix_socket("/tmp/anything.sock")


def test_build_pinned_client_constructs():
    validated = ValidatedEgressURL(
        "https://api.openai.com", "api.openai.com", 443, ("93.184.216.34",)
    )
    client = build_pinned_https_async_client(validated, policy=POLICY)
    assert client is not None
