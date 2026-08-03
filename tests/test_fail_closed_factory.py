"""Regression tests for fail-closed client construction."""

import pytest

from egressweave import (
    EgressNotAllowedError,
    EgressPolicy,
    build_egress_http_client,
    build_optional_egress_http_client,
)

POLICY = EgressPolicy.from_hosts("api.openai.com")


@pytest.mark.parametrize("value", [None, "", "   "])
async def test_required_factory_never_returns_unrestricted_client(value: str | None) -> None:
    with pytest.raises(EgressNotAllowedError, match="^egress URL is not allowed$"):
        await build_egress_http_client(value, policy=POLICY)


@pytest.mark.parametrize("value", [None, "", "   "])
async def test_optional_factory_returns_no_client_for_absent_url(value: str | None) -> None:
    assert await build_optional_egress_http_client(value, policy=POLICY) == (None, None)
