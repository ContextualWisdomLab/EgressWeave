"""Regression coverage for protocol-switching and proxy-only request fields."""

import httpx
import pytest

from egressweave import EgressNotAllowedError
from egressweave.request_safety import _build_safe_request_headers
from egressweave.sync_transport import _PinnedEgressTransport
from egressweave.transport import _PinnedEgressAsyncTransport
from egressweave.validation import _make_validated_egress_url

_FORBIDDEN_HEADER_SETS = (
    ((b"Connection", b"close"),),
    ((b"Connection", b"Upgrade"), (b"Upgrade", b"websocket")),
    ((b"Keep-Alive", b"timeout=5"),),
    ((b"Proxy-Authenticate", b'Basic realm="proxy"'),),
    ((b"Proxy-Authorization", b"Basic dXNlcjpwYXNz"),),
    ((b"Proxy-Connection", b"keep-alive"),),
    ((b"Upgrade", b"websocket"),),
)


def _validated_result():
    """Return factory-issued validation state without performing network I/O."""
    return _make_validated_egress_url(
        "https://api.openai.com",
        "api.openai.com",
        443,
        ("93.184.216.34",),
    )


class _UnexpectedSyncPool:
    """Fail if a forbidden request field reaches synchronous dispatch."""

    def handle_request(self, request):
        """Reject unexpected dispatch."""
        pytest.fail("protocol-switching request field reached the synchronous pool")


class _UnexpectedAsyncPool:
    """Fail if a forbidden request field reaches asynchronous dispatch."""

    async def handle_async_request(self, request):
        """Reject unexpected dispatch."""
        pytest.fail("protocol-switching request field reached the asynchronous pool")


def _sync_transport() -> _PinnedEgressTransport:
    """Build an offline synchronous transport double."""
    transport = object.__new__(_PinnedEgressTransport)
    transport._validated = _validated_result()
    transport._pool = _UnexpectedSyncPool()
    return transport


def _async_transport() -> _PinnedEgressAsyncTransport:
    """Build an offline asynchronous transport double."""
    transport = object.__new__(_PinnedEgressAsyncTransport)
    transport._validated = _validated_result()
    transport._pool = _UnexpectedAsyncPool()
    return transport


def _request_with_headers(headers: tuple[tuple[bytes, bytes], ...]) -> httpx.Request:
    """Preserve explicit raw fields on an otherwise offline request."""
    return httpx.Request(
        "GET",
        "https://api.openai.com/v1/models",
        headers=headers,
    )


def test_safe_header_builder_preserves_origin_authorization() -> None:
    """Keep ordinary origin credentials distinct from forbidden proxy credentials."""
    headers = _build_safe_request_headers(
        ((b"Authorization", b"Bearer provider-token"),),
        b"api.openai.com",
    )

    assert headers == [
        (b"Authorization", b"Bearer provider-token"),
        (b"host", b"api.openai.com"),
    ]


@pytest.mark.parametrize("headers", _FORBIDDEN_HEADER_SETS)
def test_safe_header_builder_rejects_protocol_switching_fields(
    headers: tuple[tuple[bytes, bytes], ...],
) -> None:
    """Reject connection controls, upgrades, and proxy-only fields."""
    with pytest.raises(EgressNotAllowedError, match="^egress URL is not allowed$"):
        _build_safe_request_headers(headers, b"api.openai.com")


@pytest.mark.parametrize("headers", _FORBIDDEN_HEADER_SETS)
def test_sync_transport_rejects_protocol_switching_fields_before_dispatch(
    headers: tuple[tuple[bytes, bytes], ...],
) -> None:
    """Enforce the field policy at the synchronous transport boundary."""
    with pytest.raises(EgressNotAllowedError, match="^egress URL is not allowed$"):
        _sync_transport().handle_request(_request_with_headers(headers))


@pytest.mark.parametrize("headers", _FORBIDDEN_HEADER_SETS)
async def test_async_transport_rejects_protocol_switching_fields_before_dispatch(
    headers: tuple[tuple[bytes, bytes], ...],
) -> None:
    """Enforce the field policy at the asynchronous transport boundary."""
    with pytest.raises(EgressNotAllowedError, match="^egress URL is not allowed$"):
        await _async_transport().handle_async_request(_request_with_headers(headers))
