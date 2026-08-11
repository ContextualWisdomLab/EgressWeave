# Safe decision evidence

EgressWeave keeps runtime rejection messages generic so an attacker cannot use
error details as a policy oracle. Operators still need deterministic evidence
that an allowed outbound decision was evaluated under the intended policy.
`build_egress_decision_evidence(...)` is the explicit opt-in boundary for that
use case.

The builder accepts a signed `ValidatedEgressURL`, revalidates it against the
current `EgressPolicy`, and returns an immutable `EgressDecisionEvidence`.
Tampered or stale validation state fails with the same generic
`EgressNotAllowedError` as transport construction.

## Versioned schema and artifact contract

`get_decision_evidence_json_schema()` loads a detached copy of
`egressweave/schemas/decision-evidence-v1.schema.json`, a JSON Schema Draft 2020-12
resource. The schema is included in both the wheel and the source distribution,
and the release verifier rejects either artifact when the
resource is missing. Callers can validate `evidence.as_dict()` without adding a
JSON Schema runtime dependency to EgressWeave.

The v1 contract requires every emitted field, including the non-empty
`address_count` total and its IPv4/IPv6 family counts. `allowed_methods` may be
an intentionally empty deny-all set, but any method token must already be an
uppercase normalized token and `CONNECT` is never accepted. These checks
describe evidence for a decision that was already authorized; the artifact is
subject to purpose limitation and does not authorize a request, path,
credential, tenant, or destination by itself.

## Data minimization

The evidence includes:

- a versioned evidence schema identifier;
- the canonical authorized hostname and port;
- the normalized allowed HTTP methods;
- aggregate IPv4, IPv6, and total address counts;
- a deterministic policy fingerprint; and
- a deterministic decision fingerprint.

It deliberately excludes request paths, resolved IP addresses, credentials,
headers, bodies, and response data. The fingerprints are canonical SHA-256
correlation values. They are not cryptographic signatures and do not protect
against arbitrary code execution inside the embedding process.

## Example

```python
from egressweave import (
    EgressPolicy,
    build_egress_decision_evidence,
    validate_egress_url_details,
)

policy = EgressPolicy.from_hosts(
    "api.example.com",
    allowed_methods={"GET", "POST"},
)
validated = validate_egress_url_details(
    "https://api.example.com/v1/models",
    policy=policy,
)
if validated is not None:
    evidence = build_egress_decision_evidence(validated, policy=policy)
    audit_sink.write(evidence.as_dict())
```

Store the evidence only in an access-controlled audit system. The authority can
still reveal service topology, so explicit operator opt-in remains required.
