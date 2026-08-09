# EgressWeave Technical Requirements Document

Status: Proposed documentation baseline. Protected-main implementation truth remains [`../../ARCHITECTURE.md`](../../ARCHITECTURE.md).

## 1. Scope and maturity

This TRD turns the product requirements in [`PRD.md`](PRD.md) into verifiable technical constraints. It distinguishes **IMPLEMENTED-ON-PROTECTED-MAIN**, **ACTIVE-PR**, **ACCEPTED-TARGET**, **PLANNED**, **RESEARCH-ONLY**, and **OUT-OF-SCOPE** behavior. An active pull request is never described as shipped.

## 2. Architectural constraints

### TRD-AR-001 — In-process library boundary

**IMPLEMENTED-ON-PROTECTED-MAIN.** EgressWeave is a Python library embedded in a host process. It does not require a resident control-plane service or package-owned database.

### TRD-AR-002 — Provider-neutral policy objects

**IMPLEMENTED-ON-PROTECTED-MAIN.** Security-sensitive configuration is represented by explicit immutable policy, TLS, timeout, and connection-pool values rather than ambient provider state.

### TRD-AR-003 — One authorization identity

**IMPLEMENTED-ON-PROTECTED-MAIN.** The normalized `(hostname, port)` authority approved before DNS remains the logical identity through validated address selection, TCP connection, TLS SNI/certificate verification, and HTTP `Host` construction.

### TRD-AR-004 — No hidden alternate egress path

**IMPLEMENTED-ON-PROTECTED-MAIN.** Guarded clients disable or reject redirect, ambient proxy, Unix-socket, caller-target, and caller-selected destination mechanisms that could create an authority not covered by policy.

## 3. Validation pipeline

The required logical pipeline is:

1. Normalize trusted policy configuration.
2. Parse and canonicalize the candidate HTTPS URL.
3. Enforce authority and method policy before DNS.
4. Resolve DNS under a finite timeout.
5. Canonicalize, deduplicate, classify, and bound address candidates.
6. Construct integrity-bound `ValidatedEgressURL` state.
7. Revalidate current policy immediately before use.
8. Connect only to accepted addresses while retaining hostname-based TLS and HTTP identity.
9. Apply request target/header/framing/body and timeout/pool controls before or during dispatch.
10. Apply response header/body/content-coding controls before caller exposure and during streaming.
11. Emit only stable public denials and bounded decision evidence.

See [`../architecture/SYSTEM_ARCHITECTURE.md`](../architecture/SYSTEM_ARCHITECTURE.md) and [`../architecture/UML.md`](../architecture/UML.md).

## 4. Security invariants

### TRD-SI-001 — Parse before resolve

Untrusted URL structure must not be sent to DNS before scheme, authority, credentials, fragments, hostname syntax, port, and method policy have been validated.

### TRD-SI-002 — Validate every DNS answer

All candidates used for connection must individually satisfy address policy. Over-limit candidate sets fail closed rather than being silently truncated into a different security decision.

### TRD-SI-003 — Preserve TLS identity

Connecting to a validated IP must not change SNI or certificate hostname verification from the originally approved hostname.

### TRD-SI-004 — Revalidate signed/integrity state

A `ValidatedEgressURL` is not a perpetual capability. Security-relevant policy drift or modified validation state must fail before network use.

### TRD-SI-005 — Stable error boundary

Dependency-private resolver, socket, TLS, stream, cleanup, and parser details must not replace the documented generic policy denial when the operation is rejected by the security boundary.

## 5. Resource controls

**IMPLEMENTED-ON-PROTECTED-MAIN** includes finite policy for:

- DNS resolution duration and maximum unique resolved addresses;
- connect/read/write/pool timeout phases;
- total and idle connection-pool capacity and idle lifetime;
- request-target bytes;
- request-header field count and bytes;
- request-body bytes through `max_request_bytes`;
- response-header field count and bytes;
- response-body bytes through `max_response_bytes`.

Exact numeric defaults are public API behavior and must be verified from the current implementation/tests when documentation is changed. Documentation must not copy a historical value without exact-head verification.

## 6. HTTP request requirements

- Method bytes must correspond to the canonical method authorized by policy.
- Raw field names/values must meet the library's strict HTTP syntax contract.
- `Host` is reconstructed from trusted authority state.
- Connection/proxy authentication and protocol-upgrade controls rejected by policy may not pass through.
- `Content-Length` and `Transfer-Encoding` must not form an ambiguous request framing state.
- Caller `target` extensions may not carry a second destination.
- Body streams are single-consumption and bounded; the first over-budget bytes are not delivered downstream.

## 7. HTTP response requirements

- Response header fanout and cumulative bytes are bounded before constructing a caller-visible response.
- Body size is checked from trustworthy metadata when possible and always enforced during stream consumption.
- Unsupported or unsafe content-coding states are rejected before decompression can turn a bounded wire response into unbounded caller allocation.
- Rejected streams are cleaned up best-effort; dependency cleanup failure remains behind the stable denial boundary while caller/coordinator cancellation semantics remain explicit.

## 8. Concurrency requirements

The asynchronous pinned backend may stagger validated address attempts, but:

- all attempts share one bounded connection deadline;
- no later candidate is launched once the deadline is exhausted;
- first accepted success wins under the documented ordering rules;
- pending and completed loser tasks/streams are deterministically reconciled;
- child failures do not become public policy provenance after all candidates fail;
- cancellation directed at the outer coordinator is not accidentally consumed by child-cleanup containment.

The synchronous backend must preserve equivalent terminal authority and error semantics where concurrency mechanics do not apply.

## 9. API and integration constraints

The public API contract is documented in [`API_CONTRACT.md`](API_CONTRACT.md). Host adapters, including naruon integration, may translate configuration and lifecycle concerns but must reuse the same security-critical policy/builder layer. The core SHALL NOT infer tenant, user, business-object, credential, queue, or persistence authority from transport policy.

## 10. Data and persistence

**OUT-OF-SCOPE.** The core package owns no durable database. Runtime objects are in-memory security/configuration/evidence objects. If a host persists audit information, that schema is host-owned and must apply independent access, retention, encryption, and privacy controls. See [`../architecture/ERD.md`](../architecture/ERD.md).

## 11. Verification requirements

- Test-first regressions for new security acceptance/rejection behavior.
- Exact 100% owned production statement and branch coverage.
- Shipped-symbol docstring completeness under repository tests.
- Supported Python matrix.
- Offline deterministic unit/integration tests without public DNS.
- Sync/async parity for shared invariants.
- Property/adversarial tests for URL, DNS, HTTP fields, framing, streams, filesystem/release evidence where applicable.
- Ruff, compileall, package build/archive verification, and installed-wheel smoke tests.
- Exact-head security scans and independent review according to repository policy.

See [`TEST_STRATEGY.md`](TEST_STRATEGY.md).

## 12. Operations, compliance, and release

Host operational ownership is defined in [`OPERABILITY.md`](OPERABILITY.md). Security/compliance contributions and limitations are mapped in [`COMPLIANCE_TRACEABILITY.md`](COMPLIANCE_TRACEABILITY.md). Standards are centralized in [`../doctoring/REFERENCES.md`](../doctoring/REFERENCES.md).

A release is **ACCEPTED-TARGET** only after the exact protected release source passes all repository-required quality, security, package, provenance/SBOM where applicable, independent review, and operational-acceptance gates. Release automation changes under an **ACTIVE-PR** remain unshipped until protected merge evidence exists.
