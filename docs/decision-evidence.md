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
