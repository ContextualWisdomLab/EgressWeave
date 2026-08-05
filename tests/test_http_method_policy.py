"""Regression tests for fail-closed HTTP method authorization."""

from __future__ import annotations

from collections.abc import AsyncIterator, Iterator

import httpx
import pytest

from egressweave.policy import DEFAULT_ALLOWED_HTTP_METHODS, EgressPolicy
from egressweave.request_safety import _enforce_allowed_http_method
from egressweave.sync_transport import _PinnedEgressTransport
from egressweave.transport import _PinnedEgressAsyncTransport
from egressweave.validation import (
    EGRESS_NOT_ALLOWED,
    EgressNotAllowedError,
    _make_validated_egress_url,
)


class _FailingCloseSyncStream(httpx.SyncByteStream):
    """Record synchronous cleanup and expose hostile exception text."""

    def __init__(self) -> None:
        """Initialize the closure marker."""
        self.closed = False

    def __iter__(self) -> Iterator[bytes]:
        """Yield one inert chunk if dispatch occurs unexpectedly."""
        yield b"body"

    def close(self) -> None:
        """Record cleanup and simulate an attacker-controlled stream failure."""
        self.closed = True
        raise RuntimeError("attacker-controlled method-denial cleanup failure")


class _FailingCloseAsyncStream(httpx.AsyncByteStream):
    """Record asynchronous cleanup and expose hostile exception text."""

    def __init__(self) -> None:
        """Initialize the asynchronous closure marker."""
        self.closed = False

    async def __aiter__(self) -> AsyncIterator[bytes]:
        """Yield one inert chunk if dispatch occurs unexpectedly."""
        yield b"body"

    async def aclose(self) -> None:
        """Record cleanup and simulate an attacker-controlled stream failure."""
        self.closed = True
        raise RuntimeError("attacker-controlled method-denial cleanup failure")


def _validated_example_url():
    return _make_validated_egress_url(
        "https://api.example.com",
        "api.example.com",
        443,
        ("93.184.216.34",),
    )


def test_default_method_policy_is_fail_closed() -> None:
    policy = EgressPolicy.from_hosts("api.example.com")

    assert policy.allowed_methods == DEFAULT_ALLOWED_HTTP_METHODS
    for method in DEFAULT_ALLOWED_HTTP_METHODS:
        _enforce_allowed_http_method(method, policy)

    for blocked_method in ("CONNECT", "TRACE", "PROPFIND"):
        with pytest.raises(
            EgressNotAllowedError,
            match=f"^{EGRESS_NOT_ALLOWED}$",
        ):
            _enforce_allowed_http_method(blocked_method, policy)


def test_method_policy_can_be_narrowed_and_normalizes_configuration() -> None:
    policy = EgressPolicy.from_hosts(
        "api.example.com",
        allowed_methods=" get, Head ",
    )

    assert policy.allowed_methods == frozenset({"GET", "HEAD"})
    assert policy.allows_http_method("get")
    assert not policy.allows_http_method("POST")
    assert not policy.allows_http_method(1)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("allowed_methods", "expected_exception"),
    [
        ({"CONNECT"}, ValueError),
        ({"BAD METHOD"}, ValueError),
        ({""}, ValueError),
        ({1}, TypeError),
    ],
)
def test_invalid_method_configuration_fails_fast(
    allowed_methods: object,
    expected_exception: type[Exception],
) -> None:
    with pytest.raises(expected_exception):
        EgressPolicy.from_hosts(
            "api.example.com",
            allowed_methods=allowed_methods,  # type: ignore[arg-type]
        )


def test_empty_method_allowlist_denies_every_request() -> None:
    policy = EgressPolicy.from_hosts("api.example.com", allowed_methods=())

    with pytest.raises(EgressNotAllowedError):
        _enforce_allowed_http_method("GET", policy)


def test_sync_transport_rejects_connect_before_network_io() -> None:
    policy = EgressPolicy.from_hosts("api.example.com")
    transport = _PinnedEgressTransport(_validated_example_url(), policy)
    try:
        request = httpx.Request("CONNECT", "https://api.example.com/")
        with pytest.raises(
            EgressNotAllowedError,
            match=f"^{EGRESS_NOT_ALLOWED}$",
        ):
            transport._verify_request_target(request)
    finally:
        transport.close()


@pytest.mark.asyncio
async def test_async_transport_rejects_connect_before_network_io() -> None:
    policy = EgressPolicy.from_hosts("api.example.com")
    transport = _PinnedEgressAsyncTransport(_validated_example_url(), policy)
    try:
        request = httpx.Request("CONNECT", "https://api.example.com/")
        with pytest.raises(
            EgressNotAllowedError,
            match=f"^{EGRESS_NOT_ALLOWED}$",
        ):
            transport._verify_request_target(request)
    finally:
        await transport.aclose()


def test_sync_method_denial_closes_request_stream_and_masks_cleanup_failure() -> None:
    """Release a denied sync body before dispatch without leaking cleanup text."""
    policy = EgressPolicy.from_hosts("api.example.com")
    transport = _PinnedEgressTransport(_validated_example_url(), policy)
    source = _FailingCloseSyncStream()
    try:
        request = httpx.Request(
            "CONNECT",
            "https://api.example.com/",
            stream=source,
        )
        with pytest.raises(
            EgressNotAllowedError,
            match=f"^{EGRESS_NOT_ALLOWED}$",
        ) as error:
            transport.handle_request(request)

        assert source.closed is True
        assert error.value.__cause__ is None
        assert error.value.__context__ is None
    finally:
        transport.close()


@pytest.mark.asyncio
async def test_async_method_denial_closes_request_stream_and_masks_cleanup_failure() -> None:
    """Release a denied async body before dispatch without leaking cleanup text."""
    policy = EgressPolicy.from_hosts("api.example.com")
    transport = _PinnedEgressAsyncTransport(_validated_example_url(), policy)
    source = _FailingCloseAsyncStream()
    try:
        request = httpx.Request(
            "CONNECT",
            "https://api.example.com/",
            stream=source,
        )
        with pytest.raises(
            EgressNotAllowedError,
            match=f"^{EGRESS_NOT_ALLOWED}$",
        ) as error:
            await transport.handle_async_request(request)

        assert source.closed is True
        assert error.value.__cause__ is None
        assert error.value.__context__ is None
    finally:
        await transport.aclose()


def test_explicit_non_tunneling_extension_method_can_be_authorized() -> None:
    policy = EgressPolicy.from_hosts(
        "api.example.com",
        allowed_methods={"PROPFIND"},
    )
    transport = _PinnedEgressTransport(_validated_example_url(), policy)
    try:
        transport._verify_request_target(
            httpx.Request("PROPFIND", "https://api.example.com/resource")
        )
    finally:
        transport.close()
