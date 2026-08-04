"""Regression tests for canonical request-method enforcement."""

from __future__ import annotations

import httpx
import pytest

from egressweave.policy import EgressPolicy
from egressweave.request_safety import _enforce_allowed_http_method
from egressweave.sync_transport import _PinnedEgressTransport
from egressweave.transport import _PinnedEgressAsyncTransport
from egressweave.validation import (
    EGRESS_NOT_ALLOWED,
    EgressNotAllowedError,
    _make_validated_egress_url,
)


def _validated_example_url():
    return _make_validated_egress_url(
        "https://api.example.com",
        "api.example.com",
        443,
        ("93.184.216.34",),
    )


@pytest.mark.parametrize(
    "method",
    [
        "get",
        " GET ",
        "GET\t",
        "G ET",
        "G\nET",
        "GÉT",
    ],
)
def test_request_boundary_rejects_noncanonical_method_tokens(method: str) -> None:
    policy = EgressPolicy.from_hosts("api.example.com")

    with pytest.raises(
        EgressNotAllowedError,
        match=f"^{EGRESS_NOT_ALLOWED}$",
    ):
        _enforce_allowed_http_method(method, policy)


def test_request_boundary_accepts_exact_authorized_method_token() -> None:
    policy = EgressPolicy.from_hosts(
        "api.example.com",
        allowed_methods={"PROPFIND"},
    )

    _enforce_allowed_http_method("PROPFIND", policy)


def test_sync_transport_rejects_whitespace_wrapped_method_before_network_io() -> None:
    policy = EgressPolicy.from_hosts("api.example.com")
    transport = _PinnedEgressTransport(_validated_example_url(), policy)
    try:
        request = httpx.Request(" GET ", "https://api.example.com/")
        with pytest.raises(
            EgressNotAllowedError,
            match=f"^{EGRESS_NOT_ALLOWED}$",
        ):
            transport._verify_request_target(request)
    finally:
        transport.close()


@pytest.mark.asyncio
async def test_async_transport_rejects_whitespace_wrapped_method_before_network_io() -> None:
    policy = EgressPolicy.from_hosts("api.example.com")
    transport = _PinnedEgressAsyncTransport(_validated_example_url(), policy)
    try:
        request = httpx.Request(" GET ", "https://api.example.com/")
        with pytest.raises(
            EgressNotAllowedError,
            match=f"^{EGRESS_NOT_ALLOWED}$",
        ):
            transport._verify_request_target(request)
    finally:
        await transport.aclose()
