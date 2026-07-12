"""egressweave — an SSRF- and DNS-rebinding-safe outbound HTTP client.

Validate an outbound URL against an explicit host allowlist, reject any
non-globally-routable target (CWE-918), and build an ``httpx.AsyncClient`` whose
every connection is pinned to the validated addresses and rejects any
post-validation host/port change (CWE-350 / DNS rebinding).

    from egressweave import EgressPolicy, build_egress_http_client

    policy = EgressPolicy.from_hosts("api.openai.com")
    normalized_url, client = await build_egress_http_client(
        "https://api.openai.com/v1", policy=policy
    )
"""

from egressweave.policy import EgressPolicy
from egressweave.transport import (
    build_egress_http_client,
    build_pinned_https_async_client,
)
from egressweave.validation import (
    EGRESS_NOT_ALLOWED,
    EgressNotAllowedError,
    ValidatedEgressURL,
    validate_egress_url,
    validate_egress_url_async,
    validate_egress_url_details,
    validate_egress_url_details_async,
)

__version__ = "0.1.0"

__all__ = [
    "EGRESS_NOT_ALLOWED",
    "EgressNotAllowedError",
    "EgressPolicy",
    "ValidatedEgressURL",
    "build_egress_http_client",
    "build_pinned_https_async_client",
    "validate_egress_url",
    "validate_egress_url_async",
    "validate_egress_url_details",
    "validate_egress_url_details_async",
]
