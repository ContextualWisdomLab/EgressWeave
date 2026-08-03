"""Regression coverage for unambiguous outbound HTTP/1.1 message framing."""

import httpx
import pytest

from egressweave import EgressNotAllowedError
from egressweave.request_safety import _build_safe_request_headers
from egressweave.sync_transport import _PinnedEgressTransport
from egressweave.transport import _PinnedEgressAsyncTransport
from egressweave.validation import _make_validated_egress_url

_INVALID_FRAMING_HEADER_SETS = (
    ((b"Content-Length", b"3"), (b"content-length", b"3")),
    ((b"Content-Length", b"3"), (b"Content-Length", b"4")),
    ((b"Content-Length", b"3"), (b"Transfer-Encoding", b"chunked")),
    ((b"Content-Length", b"+3"),),
    ((b"Content-Length", b"3, 3"),),
    ((b"Transfer-Encoding", b"gzip"),),
    ((b"Transfer-Encoding", b"gzip, chunked"),),
    ((b"Transfer-Encoding", b"chunked"), (b"transfer-encoding", b"chunked")),
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
    """Fail if ambiguous framing reaches the synchronous connection pool."""

    def handle_request(self, request):
        """Reject unexpected dispatch."""
        pytest.fail("ambiguous request framing reached the synchronous pool")


class _UnexpectedAsyncPool:
    """Fail if ambiguous framing reaches the asynchronous connection pool."""

    async def handle_async_request(self, request):
        """Reject unexpected dispatch."""
        pytest.fail("ambiguous request framing reached the asynchronous pool")


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
    """Preserve explicit framing fields on an otherwise offline request."""
    return httpx.Request(
        "POST",
        "https://api.openai.com/v1/responses",
        headers=headers,
        content=iter([b"abc"]),
    )


def test_safe_header_builder_accepts_one_decimal_content_length() -> None:
    """Preserve one canonical decimal body length and the trusted authority."""
    headers = _build_safe_request_headers(
        ((b"Content-Length", b"3"), (b"X-Trace", b"request-one")),
        b"api.openai.com",
    )

    assert headers == [
        (b"Content-Length", b"3"),
        (b"X-Trace", b"request-one"),
        (b"host", b"api.openai.com"),
    ]


def test_safe_header_builder_accepts_httpx_chunked_streaming() -> None:
    """Preserve the single chunked coding HTTPX emits for unknown-size bodies."""
    headers = _build_safe_request_headers(
        ((b"Transfer-Encoding", b"Chunked"),),
        b"api.openai.com",
    )

    assert headers == [
        (b"Transfer-Encoding", b"Chunked"),
        (b"host", b"api.openai.com"),
    ]


@pytest.mark.parametrize("headers", _INVALID_FRAMING_HEADER_SETS)
def test_safe_header_builder_rejects_ambiguous_framing(
    headers: tuple[tuple[bytes, bytes], ...],
) -> None:
    """Reject duplicate, conflicting, malformed, or unsupported framing fields."""
    with pytest.raises(EgressNotAllowedError, match="^egress URL is not allowed$"):
        _build_safe_request_headers(headers, b"api.openai.com")


@pytest.mark.parametrize("headers", _INVALID_FRAMING_HEADER_SETS)
def test_sync_transport_rejects_ambiguous_framing_before_dispatch(
    headers: tuple[tuple[bytes, bytes], ...],
) -> None:
    """Enforce framing invariants at the synchronous transport boundary."""
    with pytest.raises(EgressNotAllowedError, match="^egress URL is not allowed$"):
        _sync_transport().handle_request(_request_with_headers(headers))


@pytest.mark.parametrize("headers", _INVALID_FRAMING_HEADER_SETS)
async def test_async_transport_rejects_ambiguous_framing_before_dispatch(
    headers: tuple[tuple[bytes, bytes], ...],
) -> None:
    """Enforce framing invariants at the asynchronous transport boundary."""
    with pytest.raises(EgressNotAllowedError, match="^egress URL is not allowed$"):
        await _async_transport().handle_async_request(_request_with_headers(headers))
