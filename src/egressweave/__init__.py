"""egressweave — SSRF- and DNS-rebinding-safe outbound HTTP clients.

Validate an outbound URL against an explicit host allowlist, reject any
non-globally-routable target (CWE-918), and build synchronous or asynchronous
HTTPX clients whose connections are pinned to the validated addresses and
reject any post-validation host or port change (CWE-350 / DNS rebinding).

Synchronous usage::

    from egressweave import EgressPolicy, build_egress_sync_client

    policy = EgressPolicy.from_hosts("api.openai.com")
    normalized_url, client = build_egress_sync_client(
        "https://api.openai.com/v1", policy=policy
    )

Asynchronous usage::

    from egressweave import build_egress_http_client

    normalized_url, client = await build_egress_http_client(
        "https://api.openai.com/v1", policy=policy
    )
"""

from egressweave import policy as _policy_module
from egressweave._policy_normalization import (
    DEFAULT_MAX_RESPONSE_HEADER_BYTES,
    DEFAULT_MAX_RESPONSE_HEADER_FIELDS,
)
from egressweave.response_header_policy import EgressPolicy

_policy_module.EgressPolicy = EgressPolicy
_policy_module.DEFAULT_MAX_RESPONSE_HEADER_BYTES = DEFAULT_MAX_RESPONSE_HEADER_BYTES
_policy_module.DEFAULT_MAX_RESPONSE_HEADER_FIELDS = DEFAULT_MAX_RESPONSE_HEADER_FIELDS

from egressweave.decision_evidence import (  # noqa: E402
    DECISION_EVIDENCE_SCHEMA_VERSION,
    EgressDecisionEvidence,
    build_egress_decision_evidence,
)
from egressweave.sync_transport import (  # noqa: E402
    build_egress_sync_client,
    build_pinned_https_client,
)
from egressweave.timeout_policy import EgressTimeoutPolicy  # noqa: E402
from egressweave.tls import TLSConfiguration  # noqa: E402
from egressweave.transport import (  # noqa: E402
    build_egress_http_client,
    build_pinned_https_async_client,
)
from egressweave.validation import (  # noqa: E402
    EGRESS_NOT_ALLOWED,
    EgressNotAllowedError,
    ValidatedEgressURL,
    validate_egress_url,
    validate_egress_url_async,
    validate_egress_url_details,
    validate_egress_url_details_async,
)

__version__ = "0.3.0"

__all__ = [
    "DECISION_EVIDENCE_SCHEMA_VERSION",
    "EGRESS_NOT_ALLOWED",
    "EgressDecisionEvidence",
    "EgressNotAllowedError",
    "EgressPolicy",
    "EgressTimeoutPolicy",
    "TLSConfiguration",
    "ValidatedEgressURL",
    "build_egress_decision_evidence",
    "build_egress_http_client",
    "build_egress_sync_client",
    "build_pinned_https_async_client",
    "build_pinned_https_client",
    "validate_egress_url",
    "validate_egress_url_async",
    "validate_egress_url_details",
    "validate_egress_url_details_async",
]
