"""Regression coverage for outbound HTTP field syntax and Host authority."""

import httpx
import pytest

from egressweave import EgressNotAllowedError
from egressweave.request_safety import _build_safe_request_headers
from egressweave.sync_transport import _PinnedEgressTransport
from egressweave.transport import _PinnedEgressAsyncTransport
from egressweave.validation import _make_validated_egress_url

_INVALID_HEADER_SETS = (
    ((b"Host ", b"169.254.169.254"),),
    ((b" Host", b"169.254.169.254"),),
    ((b"X-Test", b"safe\r\nHost: 169.254.169.254"),),
    ((b"X-Test", b"\x00"),),
    ((b"X-Test", b" value"),),
    ((b"X-Test", b"value "),),
)


class _HostileHeaderBytes(bytes):
    """Fail if request-header validation executes subclass behavior."""

    def __len__(self) -> int:
        """Reject truthiness or resource accounting through this subclass."""
        raise AssertionError("header bytes subclass length executed")

    def __iter__(self):
        """Reject field-name octet iteration through this subclass."""
        raise AssertionError("header bytes subclass iteration executed")

    def __getitem__(self, key):
        """Reject field-value slicing through this subclass."""
        raise AssertionError("header bytes subclass indexing executed")

    def lower(self):
        """Reject case normalization through this subclass."""
        raise AssertionError("header bytes subclass lower executed")


def _validated_result():
    """Return factory-issued validation state without performing network I/O."""
    return _make_validated_egress_url(
        "https://api.openai.com",
        "api.openai.com",
        443,
        ("93.184.216.34",),
    )


class _UnexpectedSyncPool:
    """Fail if an invalid request reaches the synchronous connection pool."""

    def handle_request(self, request):
        """Reject unexpected dispatch."""
        pytest.fail("invalid HTTP field reached the synchronous connection pool")


class _UnexpectedAsyncPool:
    """Fail if an invalid request reaches the asynchronous connection pool."""

    async def handle_async_request(self, request):
        """Reject unexpected dispatch."""
        pytest.fail("invalid HTTP field reached the asynchronous connection pool")


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


def test_safe_header_builder_restores_one_validated_host() -> None:
    """Replace caller Host fields while preserving valid non-authority fields."""
    headers = _build_safe_request_headers(
        ((b"HOST", b"attacker.example"), (b"X-Trace", b"one\ttwo")),
        b"api.openai.com",
    )

    assert headers == [(b"X-Trace", b"one\ttwo"), (b"host", b"api.openai.com")]


@pytest.mark.parametrize(
    "headers",
    (
        ((_HostileHeaderBytes(b"X-Test"), b"value"),),
        ((b"X-Test", _HostileHeaderBytes(b"value")),),
    ),
)
def test_safe_header_builder_rejects_bytes_subclasses_before_custom_behavior(
    headers: tuple[tuple[bytes, bytes], ...],
) -> None:
    """Reject header subclasses before invoking attacker-controlled protocols."""
    with pytest.raises(
        EgressNotAllowedError, match="^egress URL is not allowed$"
    ) as error:
        _build_safe_request_headers(headers, b"api.openai.com")

    assert error.value.__cause__ is None
    assert error.value.__context__ is None


@pytest.mark.parametrize("headers", _INVALID_HEADER_SETS)
def test_safe_header_builder_rejects_malformed_fields(
    headers: tuple[tuple[bytes, bytes], ...],
) -> None:
    """Reject field syntax that can produce parser or routing ambiguity."""
    with pytest.raises(EgressNotAllowedError, match="^egress URL is not allowed$"):
        _build_safe_request_headers(headers, b"api.openai.com")


@pytest.mark.parametrize("headers", _INVALID_HEADER_SETS)
def test_sync_transport_rejects_malformed_fields_before_dispatch(
    headers: tuple[tuple[bytes, bytes], ...],
) -> None:
    """Apply raw-field validation at the synchronous transport boundary."""
    request = httpx.Request(
        "GET",
        "https://api.openai.com/v1/models",
        headers=headers,
    )

    with pytest.raises(EgressNotAllowedError, match="^egress URL is not allowed$"):
        _sync_transport().handle_request(request)


@pytest.mark.parametrize("headers", _INVALID_HEADER_SETS)
async def test_async_transport_rejects_malformed_fields_before_dispatch(
    headers: tuple[tuple[bytes, bytes], ...],
) -> None:
    """Apply raw-field validation at the asynchronous transport boundary."""
    request = httpx.Request(
        "GET",
        "https://api.openai.com/v1/models",
        headers=headers,
    )

    with pytest.raises(EgressNotAllowedError, match="^egress URL is not allowed$"):
        await _async_transport().handle_async_request(request)
