"""Focused coverage for the last reachable validation and connection-race branches."""

from __future__ import annotations

from egressweave import EgressPolicy, validate_egress_url, validation
from egressweave import transport as async_transport
from egressweave.transport import _PinnedEgressNetworkBackend

PUBLIC_ADDRESS = "93.184.216.34"
SECOND_PUBLIC_ADDRESS = "93.184.216.35"
POLICY = EgressPolicy.from_hosts("api.example.com")


class _AsyncStream:
    """Minimal successful stream returned by the second pinned address."""

    async def aclose(self) -> None:
        """Close the stateless synthetic stream."""


def test_validate_egress_url_returns_a_normalized_success(monkeypatch) -> None:
    """Cover the synchronous convenience wrapper's successful return branch."""
    monkeypatch.setattr(
        validation.socket,
        "getaddrinfo",
        lambda host, port, type=None: [
            (2, 1, 6, "", (PUBLIC_ADDRESS, port))
        ],
    )

    assert (
        validate_egress_url("https://API.Example.com/v1", policy=POLICY)
        == "https://api.example.com/v1"
    )


async def test_async_backend_advances_immediately_after_first_failure(
    monkeypatch,
) -> None:
    """Start the next validated address after an immediate failed attempt."""
    backend = _PinnedEgressNetworkBackend(
        "api.example.com",
        443,
        (PUBLIC_ADDRESS, SECOND_PUBLIC_ADDRESS),
        POLICY,
    )
    attempted: list[str] = []
    stream = _AsyncStream()

    async def connect(address, port, timeout, local_address, socket_options):
        attempted.append(address)
        if address == PUBLIC_ADDRESS:
            raise OSError("first pinned address failed")
        return stream

    monkeypatch.setattr(backend, "_connect_validated_ip_address", connect)
    monkeypatch.setattr(async_transport, "_CONNECTION_ATTEMPT_DELAY_SECONDS", 60.0)

    assert await backend.connect_tcp("api.example.com", 443, timeout=1.0) is stream
    assert attempted == [PUBLIC_ADDRESS, SECOND_PUBLIC_ADDRESS]
