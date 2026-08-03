"""Regression coverage for low-level HTTP request-target authority drift."""

import httpx
import pytest

from egressweave import EgressNotAllowedError
from egressweave.sync_transport import _PinnedEgressTransport
from egressweave.transport import _PinnedEgressAsyncTransport
from egressweave.validation import _make_validated_egress_url


def _validated_result():
    """Return factory-issued validation state without performing network I/O."""
    return _make_validated_egress_url(
        "https://api.openai.com",
        "api.openai.com",
        443,
        ("93.184.216.34",),
    )


class _UnexpectedSyncPool:
    """Fail if a rejected request reaches the synchronous connection pool."""

    def handle_request(self, request):
        pytest.fail("request-target extension reached the connection pool")


class _UnexpectedAsyncPool:
    """Fail if a rejected request reaches the asynchronous connection pool."""

    async def handle_async_request(self, request):
        pytest.fail("request-target extension reached the connection pool")


def _absolute_target_request() -> httpx.Request:
    """Build an allowlisted URL carrying a proxy-style absolute target override."""
    return httpx.Request(
        "GET",
        "https://api.openai.com/v1/models",
        extensions={
            "target": b"http://169.254.169.254/latest/meta-data/iam/security-credentials/"
        },
    )


def test_sync_transport_rejects_httpcore_target_extension() -> None:
    """Do not let absolute-form targets bypass the pinned sync authority."""
    transport = object.__new__(_PinnedEgressTransport)
    transport._validated = _validated_result()
    transport._pool = _UnexpectedSyncPool()

    with pytest.raises(EgressNotAllowedError, match="^egress URL is not allowed$"):
        transport.handle_request(_absolute_target_request())


async def test_async_transport_rejects_httpcore_target_extension() -> None:
    """Do not let absolute-form targets bypass the pinned async authority."""
    transport = object.__new__(_PinnedEgressAsyncTransport)
    transport._validated = _validated_result()
    transport._pool = _UnexpectedAsyncPool()

    with pytest.raises(EgressNotAllowedError, match="^egress URL is not allowed$"):
        await transport.handle_async_request(_absolute_target_request())
