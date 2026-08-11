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

## Versioned machine-readable contract

The runtime mapping is published as the packaged JSON Schema Draft 2020-12
resource `egressweave/schemas/decision-evidence-v1.schema.json`. Downstream
SIEM, GRC, gateway, and MSA consumers can therefore validate an exported record
without importing EgressWeave's implementation classes or copying an internal
schema.

`get_decision_evidence_json_schema()` loads the trusted packaged resource and
returns a fresh detached mapping on every call. Caller mutation cannot change a
later load or package state. The loader uses only the Python standard library;
EgressWeave does not require a JSON Schema validation dependency at runtime.

The schema's `schema_version` `const` is required to equal
`DECISION_EVIDENCE_SCHEMA_VERSION`, currently
`egressweave.decision-evidence.v1`. It requires exactly the runtime evidence
fields and sets `additionalProperties` to `false`, so unexpected fields do not
silently become part of the v1 interchange contract. Fingerprints retain their
lowercase 64-hex SHA-256 shape. The schema requires the non-empty total
`address_count` and also publishes non-negative IPv4 and IPv6 family counts;
the runtime derives the total from those family counts, so consumers can verify
that the three values are consistent even when either family is absent. The
`allowed_methods` array may be empty because
`EgressPolicy` supports
an intentional deny-all method set. When entries are present, the v1 evidence
contract accepts only the uppercase RFC 9110 `token` character subset that
EgressWeave's policy normalization can emit, requires entries to be unique, and
rejects `CONNECT`, which EgressWeave never authorizes. The schema therefore
rejects lowercase, whitespace-bearing, non-ASCII, and `CONNECT` method strings
that cannot be emitted by the current runtime evidence builder. It omits
`minItems` because JSON Schema Draft 2020-12 defines an omitted `minItems` as
equivalent to zero, matching the public runtime record rather than rejecting a
valid `EgressDecisionEvidence.as_dict()` result.

RFC 9110 defines an HTTP method as a case-sensitive `token` and notes that
standardized method names are conventionally uppercase. EgressWeave's uppercase
policy canonicalization is therefore an explicit product contract for this v1
evidence schema, not a claim that arbitrary extension methods are inherently
case-insensitive. A future change to method canonicalization would require a
versioned compatibility decision for this interchange contract.

A consumer remains responsible for selecting and operating a conforming Draft
2020-12 validator. The schema describes structure and interchange validity; it
does **not** turn the correlation fingerprints into signatures, prove event
origin, or authorize an egress operation.

## Data minimization

The evidence includes:

- a versioned evidence schema identifier;
- the canonical authorized hostname and port;
- the normalized allowed HTTP methods;
- the non-empty total resolved-address count;
- aggregate IPv4 and IPv6 address counts;
- a deterministic policy fingerprint; and
- a deterministic decision fingerprint.

It deliberately excludes request paths, resolved IP addresses, credentials,
headers, bodies, and response data. The fingerprints are canonical SHA-256
correlation values. They are not cryptographic signatures and do not protect
against arbitrary code execution inside the embedding process.

The canonical authority can still reveal service topology. Store evidence only
in an access-controlled audit system with purpose limitation, tenant/role
separation, retention controls, and access logging appropriate to the host
application. Do not send the record to an LLM or third-party telemetry sink
merely because it omits request content.

## Example

```python
from egressweave import (
    EgressPolicy,
    build_egress_decision_evidence,
    get_decision_evidence_json_schema,
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

schema = get_decision_evidence_json_schema()
```

## References

Bray, T. (2017). *The JavaScript Object Notation (JSON) data interchange
format* (RFC 8259). RFC Editor. https://doi.org/10.17487/RFC8259

Fielding, R., Nottingham, M., & Reschke, J. (2022). *HTTP semantics* (RFC 9110).
RFC Editor. https://doi.org/10.17487/RFC9110

Wright, A., Andrews, H., Hutton, B., & Dennis, G. (2022). *JSON Schema Draft
2020-12*. JSON Schema. https://json-schema.org/draft/2020-12
