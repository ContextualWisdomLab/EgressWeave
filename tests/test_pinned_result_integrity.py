"""Regression tests for forged ``ValidatedEgressURL`` inputs."""

import pytest

from egressweave import (
    EgressNotAllowedError,
    EgressPolicy,
    ValidatedEgressURL,
    build_pinned_https_async_client,
)

POLICY = EgressPolicy.from_hosts("api.openai.com")


@pytest.mark.parametrize(
    "validated, policy",
    [
        (
            ValidatedEgressURL(
                "https://evil.example",
                "evil.example",
                443,
                ("93.184.216.34",),
            ),
            POLICY,
        ),
        (
            ValidatedEgressURL(
                "http://api.openai.com",
                "api.openai.com",
                80,
                ("93.184.216.34",),
            ),
            POLICY,
        ),
        (
            ValidatedEgressURL(
                "https://api.openai.com",
                "api.anthropic.com",
                443,
                ("93.184.216.34",),
            ),
            EgressPolicy.from_hosts("api.openai.com,api.anthropic.com"),
        ),
        (
            ValidatedEgressURL(
                "https://api.openai.com:8443",
                "api.openai.com",
                443,
                ("93.184.216.34",),
            ),
            POLICY,
        ),
    ],
    ids=[
        "host-not-allowlisted",
        "remote-plaintext-http",
        "url-hostname-mismatch",
        "url-port-mismatch",
    ],
)
def test_build_pinned_client_rejects_forged_validation_result(
    validated: ValidatedEgressURL, policy: EgressPolicy
) -> None:
    with pytest.raises(EgressNotAllowedError):
        build_pinned_https_async_client(validated, policy=policy)
