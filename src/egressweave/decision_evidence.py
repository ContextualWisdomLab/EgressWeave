"""Deterministic, non-secret evidence for successful egress decisions.

The runtime rejection boundary deliberately exposes only a generic error. This
module provides an explicit opt-in audit record for already validated, allowed
decisions without recording request paths, resolved IP addresses, credentials,
or response data. The versioned evidence shape is also published as a packaged
JSON Schema so downstream audit systems can validate the contract without
coupling to EgressWeave implementation details.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from egressweave.policy import EgressPolicy
from egressweave.validation import (
    ValidatedEgressURL,
    _revalidate_pinned_egress_url,
)

DECISION_EVIDENCE_SCHEMA_VERSION = "egressweave.decision-evidence.v1"
_DECISION_EVIDENCE_SCHEMA_FILENAME = "decision-evidence-v1.schema.json"


def get_decision_evidence_json_schema() -> dict[str, object]:
    """Return a fresh JSON-compatible copy of the packaged evidence schema.

    The resource uses JSON Schema Draft 2020-12 and describes exactly the
    versioned mapping emitted by :meth:`EgressDecisionEvidence.as_dict`. Reading
    and decoding the trusted package resource for each call deliberately avoids
    shared mutable schema state and does not require a JSON Schema dependency.
    """
    schema_path = Path(__file__).with_name("schemas") / _DECISION_EVIDENCE_SCHEMA_FILENAME
    with schema_path.open("r", encoding="utf-8") as schema_file:
        return cast(dict[str, object], json.load(schema_file))


def _sha256_canonical_json(payload: dict[str, object]) -> str:
    """Return a lowercase SHA-256 digest of canonical ASCII JSON."""
    serialized = json.dumps(
        payload,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    return hashlib.sha256(serialized).hexdigest()


def _policy_fingerprint(policy: EgressPolicy) -> str:
    """Fingerprint normalized policy fields without retaining configuration text."""
    payload: dict[str, object] = {
        "allowed_authorities": [
            [hostname, port]
            for hostname, port in sorted(policy.allowed_authorities)
        ],
        "allowed_methods": sorted(policy.allowed_methods),
        "allow_local": policy.allow_local,
        "connection_pool_policy": {
            "keepalive_expiry_seconds": repr(
                policy.connection_pool_policy.keepalive_expiry_seconds
            ),
            "max_connections": policy.connection_pool_policy.max_connections,
            "max_keepalive_connections": (
                policy.connection_pool_policy.max_keepalive_connections
            ),
        },
        "dns_timeout_seconds": repr(policy.dns_timeout_seconds),
        "max_resolved_addresses": policy.max_resolved_addresses,
        "max_request_bytes": policy.max_request_bytes,
        "max_request_header_fields": policy.max_request_header_fields,
        "max_request_header_bytes": policy.max_request_header_bytes,
        "max_request_target_bytes": policy.max_request_target_bytes,
        "max_response_bytes": policy.max_response_bytes,
        "max_response_header_fields": policy.max_response_header_fields,
        "max_response_header_bytes": policy.max_response_header_bytes,
        "request_timeout_policy": {
            key: repr(value)
            for key, value in policy.request_timeout_policy.as_httpcore_timeout().items()
        },
    }
    return _sha256_canonical_json(payload)


@dataclass(frozen=True)
class EgressDecisionEvidence:
    """Immutable audit evidence for one successfully authorized authority.

    The record intentionally omits the request path and every resolved address.
    Fingerprints are deterministic correlation values, not signatures or message
    authentication codes, and must not be treated as proof against a process
    that can execute arbitrary Python code.
    """

    schema_version: str
    authority: str
    allowed_methods: tuple[str, ...]
    address_count: int
    ipv4_address_count: int
    ipv6_address_count: int
    policy_fingerprint: str
    decision_fingerprint: str

    def as_dict(self) -> dict[str, object]:
        """Return a detached JSON-compatible representation of this evidence."""
        return {
            "schema_version": self.schema_version,
            "authority": self.authority,
            "allowed_methods": list(self.allowed_methods),
            "address_count": self.address_count,
            "ipv4_address_count": self.ipv4_address_count,
            "ipv6_address_count": self.ipv6_address_count,
            "policy_fingerprint": self.policy_fingerprint,
            "decision_fingerprint": self.decision_fingerprint,
        }


def build_egress_decision_evidence(
    validated: ValidatedEgressURL,
    *,
    policy: EgressPolicy,
) -> EgressDecisionEvidence:
    """Build safe deterministic evidence after revalidating signed state.

    Tampered, stale, or policy-incompatible validation results preserve the
    generic :class:`~egressweave.validation.EgressNotAllowedError` boundary.
    Successful evidence contains only the canonical authority, policy method
    names, aggregate address-family counts, and deterministic fingerprints.
    """
    revalidated = _revalidate_pinned_egress_url(validated, policy)
    versions = tuple(
        ipaddress.ip_address(address).version for address in revalidated.addresses
    )
    policy_digest = _policy_fingerprint(policy)
    evidence_payload: dict[str, object] = {
        "schema_version": DECISION_EVIDENCE_SCHEMA_VERSION,
        "authority": f"{revalidated.hostname}:{revalidated.port}",
        "allowed_methods": sorted(policy.allowed_methods),
        "address_count": len(versions),
        "ipv4_address_count": versions.count(4),
        "ipv6_address_count": versions.count(6),
        "policy_fingerprint": policy_digest,
    }
    decision_digest = _sha256_canonical_json(evidence_payload)
    return EgressDecisionEvidence(
        schema_version=DECISION_EVIDENCE_SCHEMA_VERSION,
        authority=str(evidence_payload["authority"]),
        allowed_methods=tuple(sorted(policy.allowed_methods)),
        address_count=len(versions),
        ipv4_address_count=versions.count(4),
        ipv6_address_count=versions.count(6),
        policy_fingerprint=policy_digest,
        decision_fingerprint=decision_digest,
    )
