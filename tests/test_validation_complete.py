"""Complete branch coverage for validation helpers and failure paths."""

from __future__ import annotations

import asyncio
import socket

import pytest

from egressweave import EgressNotAllowedError, EgressPolicy
from egressweave import validation as v

PUBLIC_ADDRESS = "93.184.216.34"
REMOTE_POLICY = EgressPolicy.from_hosts("api.openai.com")


def test_ip_literal_and_netloc_helpers_cover_canonical_forms() -> None:
    assert v._is_ip_literal(PUBLIC_ADDRESS) is True
    assert v._is_ip_literal("api.openai.com") is False
    assert v._looks_like_ip_literal("0x7f000001") is True
    assert v._looks_like_ip_literal("api.openai.com") is False
    assert v._format_normalized_netloc("::1", 8443, explicit_port=True) == "[::1]:8443"


def test_invalid_address_text_is_rejected() -> None:
    with pytest.raises(EgressNotAllowedError, match="^egress URL is not allowed$"):
        v._validate_global_address("not-an-address", REMOTE_POLICY)


def test_resolver_wraps_dns_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail_resolution(hostname: str, port: int, type: int) -> list[object]:
        raise socket.gaierror("synthetic failure")

    monkeypatch.setattr(v.socket, "getaddrinfo", fail_resolution)

    with pytest.raises(EgressNotAllowedError, match="^egress URL is not allowed$"):
        v._resolve_all_global_addresses("api.openai.com", 443, REMOTE_POLICY)


def test_resolver_rejects_empty_results(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(v.socket, "getaddrinfo", lambda *args, **kwargs: [])

    with pytest.raises(EgressNotAllowedError, match="^egress URL is not allowed$"):
        v._resolve_all_global_addresses("api.openai.com", 443, REMOTE_POLICY)


def test_resolver_canonicalizes_and_deduplicates(monkeypatch: pytest.MonkeyPatch) -> None:
    def duplicate_results(hostname: str, port: int, type: int) -> list[tuple]:
        return [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", (PUBLIC_ADDRESS, port)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", (PUBLIC_ADDRESS, port)),
        ]

    monkeypatch.setattr(v.socket, "getaddrinfo", duplicate_results)

    assert v._resolve_all_global_addresses("api.openai.com", 443, REMOTE_POLICY) == (
        PUBLIC_ADDRESS,
    )


async def test_async_resolver_wraps_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fail_with_timeout(awaitable, *, timeout: float):
        awaitable.close()
        raise asyncio.TimeoutError

    monkeypatch.setattr(v.asyncio, "wait_for", fail_with_timeout)

    with pytest.raises(EgressNotAllowedError, match="^egress URL is not allowed$"):
        await v._resolve_all_global_addresses_async(
            "api.openai.com", 443, REMOTE_POLICY
        )


@pytest.mark.parametrize(
    "candidate",
    ["https://api.openai.com:99999", "https://[::1"],
    ids=["out-of-range-port", "malformed-ipv6"],
)
def test_parser_wraps_urlsplit_value_errors(candidate: str) -> None:
    with pytest.raises(EgressNotAllowedError, match="^egress URL is not allowed$"):
        v._parse_and_validate_candidate_url(candidate)


@pytest.mark.parametrize(
    "policy",
    [EgressPolicy.from_hosts([]), EgressPolicy.from_hosts("*")],
    ids=["empty", "wildcard"],
)
def test_remote_policy_rejects_empty_or_wildcard_allowlists(policy: EgressPolicy) -> None:
    with pytest.raises(EgressNotAllowedError, match="^egress URL is not allowed$"):
        v._normalize_egress_url("https://api.openai.com", policy)


@pytest.mark.parametrize("host", [PUBLIC_ADDRESS, "0x7f000001"])
def test_remote_policy_rejects_allowlisted_ip_literal_forms(host: str) -> None:
    policy = EgressPolicy.from_hosts(host)

    with pytest.raises(EgressNotAllowedError, match="^egress URL is not allowed$"):
        v._normalize_egress_url(f"https://{host}", policy)


def test_local_url_skips_remote_allowlist_and_preserves_explicit_port() -> None:
    policy = EgressPolicy.from_hosts([], allow_local=True, allowed_ports=(11434,))

    normalized, hostname, port = v._normalize_egress_url(
        "http://LOCALHOST:11434/v1", policy
    )

    assert normalized == "http://localhost:11434/v1"
    assert hostname == "localhost"
    assert port == 11434


def test_signed_but_internally_inconsistent_result_is_rejected() -> None:
    inconsistent = v._make_validated_egress_url(
        "https://api.openai.com",
        "api.anthropic.com",
        443,
        (PUBLIC_ADDRESS,),
    )

    with pytest.raises(EgressNotAllowedError, match="^egress URL is not allowed$"):
        v._revalidate_pinned_egress_url(inconsistent, REMOTE_POLICY)


def test_validate_egress_url_returns_normalized_url(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        v.socket,
        "getaddrinfo",
        lambda host, port, type=None: [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", (PUBLIC_ADDRESS, port))
        ],
    )

    assert (
        v.validate_egress_url("https://API.OpenAI.com/v1", policy=REMOTE_POLICY)
        == "https://api.openai.com/v1"
    )


async def test_async_validation_empty_paths_return_none() -> None:
    assert await v.validate_egress_url_details_async(None, policy=REMOTE_POLICY) is None
    assert await v.validate_egress_url_async("   ", policy=REMOTE_POLICY) is None
