import math
import threading
import time

import pytest

from egressweave import (
    EgressNotAllowedError,
    EgressPolicy,
    validate_egress_url_details,
    validate_egress_url_details_async,
)
from egressweave import validation as v


@pytest.mark.parametrize(
    "timeout",
    [0, -1, math.inf, math.nan, True, "1"],
    ids=["zero", "negative", "infinite", "nan", "boolean", "string"],
)
def test_policy_rejects_invalid_dns_timeout(timeout):
    with pytest.raises(
        ValueError, match="^dns_timeout_seconds must be a finite positive number$"
    ):
        EgressPolicy.from_hosts(
            "api.openai.com",
            dns_timeout_seconds=timeout,
        )


def test_policy_canonicalizes_numeric_dns_timeout():
    policy = EgressPolicy.from_hosts("api.openai.com", dns_timeout_seconds=2)

    assert policy.dns_timeout_seconds == 2.0
    assert isinstance(policy.dns_timeout_seconds, float)


def _install_blocking_resolver(monkeypatch):
    started = threading.Event()
    release = threading.Event()

    def fake_getaddrinfo(host, port, type=None):
        started.set()
        release.wait(timeout=2.0)
        return [(2, 1, 6, "", ("93.184.216.34", port))]

    monkeypatch.setattr(v.socket, "getaddrinfo", fake_getaddrinfo)
    return started, release


def test_sync_validation_enforces_dns_timeout(monkeypatch):
    started, release = _install_blocking_resolver(monkeypatch)
    policy = EgressPolicy.from_hosts(
        "api.openai.com",
        dns_timeout_seconds=0.05,
    )
    started_at = time.monotonic()

    try:
        with pytest.raises(
            EgressNotAllowedError, match="^egress URL is not allowed$"
        ):
            validate_egress_url_details(
                "https://api.openai.com/v1",
                policy=policy,
            )
        assert started.wait(timeout=0.2)
        assert time.monotonic() - started_at < 0.5
    finally:
        release.set()


async def test_async_validation_uses_same_bounded_dns_timeout(monkeypatch):
    started, release = _install_blocking_resolver(monkeypatch)
    policy = EgressPolicy.from_hosts(
        "api.openai.com",
        dns_timeout_seconds=0.05,
    )
    started_at = time.monotonic()

    try:
        with pytest.raises(
            EgressNotAllowedError, match="^egress URL is not allowed$"
        ):
            await validate_egress_url_details_async(
                "https://api.openai.com/v1",
                policy=policy,
            )
        assert started.wait(timeout=0.2)
        assert time.monotonic() - started_at < 0.5
    finally:
        release.set()


def test_resolver_failure_remains_generic(monkeypatch):
    def broken_getaddrinfo(host, port, type=None):
        raise UnicodeError("resolver-specific detail")

    monkeypatch.setattr(v.socket, "getaddrinfo", broken_getaddrinfo)
    policy = EgressPolicy.from_hosts("api.openai.com")

    with pytest.raises(EgressNotAllowedError) as error:
        validate_egress_url_details("https://api.openai.com/v1", policy=policy)

    assert str(error.value) == "egress URL is not allowed"
