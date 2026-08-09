# EgressWeave Product Requirements Document

Status: Proposed documentation baseline for protected-main behavior and accepted product direction.

## 1. Product definition

EgressWeave is a provider-neutral outbound HTTP security library for Python applications that need explicit, reviewable egress authority instead of ambient network trust. It is intended to be useful as a standalone package and as a modular dependency that host-owned adapters in naruon and other ContextualWisdomLab services can consume.

The authoritative description of behavior already implemented on the protected branch is the repository-root [`ARCHITECTURE.md`](../../ARCHITECTURE.md). This PRD expresses buyer problems, product requirements, acceptance criteria, and ownership boundaries; it does not replace implementation architecture.

## 2. Maturity vocabulary

Every requirement or design claim in the product documentation uses one of these states:

- **IMPLEMENTED-ON-PROTECTED-MAIN** — verified behavior in the current protected branch.
- **ACTIVE-PR** — implemented or being implemented on an unmerged pull request; not shipped.
- **ACCEPTED-TARGET** — a reviewed direction that still requires implementation and merge evidence.
- **PLANNED** — backlog or design intent without accepted implementation evidence.
- **RESEARCH-ONLY** — evidence under evaluation and not a product contract.
- **OUT-OF-SCOPE** — deliberately owned by a host, platform, or another product.

## 3. Buyer problems

Enterprise application teams need to call approved remote services without allowing ordinary application code, configuration drift, DNS rebinding, proxy inheritance, redirects, malformed HTTP framing, or resource-exhaustion paths to widen destination authority. Security teams also need deterministic failure semantics and bounded decision evidence that can be audited without leaking request payloads or resolved infrastructure details.

EgressWeave addresses those problems in-process while remaining complementary to network firewalls, service-mesh egress gateways, operating-system isolation, and application authorization.

## 4. Primary users

### Platform and application engineers

They need a small API that converts an approved base URL and explicit policy into reusable synchronous or asynchronous HTTPX clients without hand-building resolver, TLS, proxy, framing, or cleanup defenses.

### Security engineers

They need destination authorization to remain stable from configuration through DNS resolution, connection establishment, TLS identity, HTTP authority, request framing, response handling, and failure cleanup.

### Compliance, procurement, and operations reviewers

They need documented control contributions, reproducible package and release evidence, understandable non-goals, and a clear division between controls the library implements and controls the host organization must operate.

## 5. Product goals

### PRD-G-001 — Fail-closed egress authority

**IMPLEMENTED-ON-PROTECTED-MAIN.** Only explicitly authorized normalized hostname/port combinations and methods may reach network dispatch. Untrusted URL parsing, DNS results, request metadata, transport errors, and cleanup failures must not silently widen authority.

### PRD-G-002 — DNS-rebinding-resistant connection binding

**IMPLEMENTED-ON-PROTECTED-MAIN.** The client validates address candidates, binds accepted validation state to the authority, and connects only to validated addresses while preserving the original hostname for TLS identity and HTTP authority.

### PRD-G-003 — Finite resource use

**IMPLEMENTED-ON-PROTECTED-MAIN.** DNS candidates, connection attempts, pool capacity, timeout phases, request targets, request headers, request bodies, response headers, and response bodies have explicit finite policies or secure finite defaults.

### PRD-G-004 — Provider-neutral modular integration

**IMPLEMENTED-ON-PROTECTED-MAIN.** The core public policy, validation, TLS, and transport contracts are not coupled to one cloud, model provider, gateway, or host product and can be consumed by host-owned integration adapters without a second security implementation. The naruon adapter itself is **OUT-OF-SCOPE** for the EgressWeave package and remains host-owned.

### PRD-G-005 — Evidence without payload disclosure

**IMPLEMENTED-ON-PROTECTED-MAIN** for runtime decision evidence exposed by the current public API. Evidence records normalized authority and bounded policy facts without treating request/response bodies, credentials, paths, or resolved IP addresses as routine audit output.

### PRD-G-006 — Commercially defensible engineering evidence

**IMPLEMENTED-ON-PROTECTED-MAIN** for exact 100% owned production statement/branch coverage, public docstring contracts, package acceptance, and multiple security checks. Supply-chain/release hardening beyond the protected-main baseline may exist as **ACTIVE-PR** work and must not be described as shipped until merged.

## 6. Functional requirements

### PRD-FR-001 — Policy construction

The library SHALL construct immutable policies from explicitly allowed hosts or normalized authorities, ports, and methods. Ambiguous configuration SHALL fail during trusted startup rather than silently broadening permissions.

### PRD-FR-002 — URL validation

The library SHALL reject credentials, fragments, unsupported schemes, IP-literal destinations, malformed hostnames, unauthorized ports, and unauthorized methods before transport dispatch. Internationalized names SHALL resolve to one canonical comparison/TLS identity under the documented normalization rules.

### PRD-FR-003 — Address validation

The library SHALL validate every returned address against the selected policy, reject disallowed address classes, cap the number of unique candidates, and preserve enough integrity-bound state to detect later policy drift or tampering before use.

### PRD-FR-004 — Pinned connection behavior

Synchronous and asynchronous transports SHALL connect to validated addresses while keeping the approved hostname as the TLS server name and HTTP authority. Caller-selected proxy destinations, Unix sockets, or alternate transport targets SHALL not bypass this binding.

### PRD-FR-005 — TLS policy

The public client builders SHALL support explicit immutable TLS configuration, including private trust stores and client identities where configured, while keeping secure protocol defaults and certificate verification enabled.

### PRD-FR-006 — Request semantics

Before dispatch the library SHALL enforce canonical authorized methods, trusted `Host` handling, forbidden connection/proxy upgrade controls, unambiguous request-body framing, valid field syntax, finite target size, finite header fanout/bytes, finite request-body consumption, and finite timeout/pool policy.

### PRD-FR-007 — Response semantics

Before exposing a response and while streaming its body, the library SHALL enforce finite header fanout/bytes, safe content-length handling, the documented content-coding boundary, exact byte accounting, and the configured `max_response_bytes` limit. Policy-denied sources SHALL be cleaned up best-effort without replacing the stable public denial with dependency-private failure details.

### PRD-FR-008 — Stable denials

Policy failures SHALL surface through the stable public denial contract rather than leak resolver, transport, filesystem, cleanup, or dependency-specific details that can become an information oracle.

### PRD-FR-009 — Sync/async parity

Security invariants shared by synchronous and asynchronous clients SHALL be covered by equivalent behavior and regression evidence unless an explicitly documented runtime difference makes parity inapplicable.

### PRD-FR-010 — Decision evidence

The package SHALL provide deterministic, bounded decision evidence for accepted egress decisions without asserting causal, certification, or infrastructure facts it cannot establish.

### PRD-FR-011 — Standalone and host-owned integration

EgressWeave public policy and builder contracts SHALL remain suitable for host-owned naruon and CWL adapters. Host-specific configuration translation SHALL remain outside core and SHALL reuse the public EgressWeave security path rather than introduce a second transport implementation.

## 7. Non-functional requirements

### Security

- Fail closed on malformed or ambiguous security inputs.
- Never enable redirects or ambient proxy inheritance in guarded clients.
- Keep secrets and payload contents outside routine library evidence.
- Preserve exact authority across DNS, TCP, TLS, and HTTP layers.

### Reliability

- Bound waits and resource consumption.
- Cancel and clean up loser tasks and rejected streams deterministically.
- Preserve outer coordinator cancellation where cancellation is part of caller control flow.

### Compatibility

- Support the Python versions declared in package metadata and CI.
- Keep the public API stable within the pre-1.0 compatibility policy documented in [`API_CONTRACT.md`](API_CONTRACT.md).
- Use explicit dependency contracts rather than undocumented private defaults where a security decision depends on them.

### Quality

- Owned production statement coverage: 100%.
- Owned production branch coverage: 100%.
- Public/shipped symbol docstrings: 100% under the repository contract.
- Deterministic offline regressions for security boundaries.
- Wheel and source-distribution acceptance before release.

## 8. Explicit non-goals

The following are **OUT-OF-SCOPE** for EgressWeave core unless a future accepted ADR changes ownership:

- application-level authorization for URL paths, query semantics, request bodies, business objects, API keys, OAuth scopes, users, or tenants;
- malware classification or semantic inspection of response payloads;
- durable databases, tenant stores, queues, application audit stores, or retention policy enforcement;
- host-specific integration-adapter implementation and lifecycle, including naruon configuration translation;
- replacing a firewall, service mesh, cloud egress control, sandbox, or operating-system isolation;
- arbitrary proxy support, Unix sockets, redirects across authorities, or caller-selected destination IPs;
- blanket PII masking that would change legitimate application payload behavior.

## 9. Commercial acceptance criteria

A buyer-facing release is acceptable only when the exact protected release source satisfies the repository's required CI, security, coverage/docstring, packaging, dependency/supply-chain, provenance/SBOM where applicable, independent review, release and operational-acceptance gates. A green feature branch, model review comment, or stale predecessor check is not release evidence.

Host organizations remain responsible for service-level objectives, incident operations, tenant access control, secrets, application logging/retention, host-owned adapters, and network-layer enforcement. See [`OPERABILITY.md`](OPERABILITY.md) and [`COMPLIANCE_TRACEABILITY.md`](COMPLIANCE_TRACEABILITY.md).

## 10. Documentation spine

- Technical requirements: [`TRD.md`](TRD.md)
- Implementation architecture: [`../../ARCHITECTURE.md`](../../ARCHITECTURE.md)
- Supplementary system views: [`../architecture/SYSTEM_ARCHITECTURE.md`](../architecture/SYSTEM_ARCHITECTURE.md)
- API contract: [`API_CONTRACT.md`](API_CONTRACT.md)
- Threat model: [`../THREAT_MODEL.md`](../THREAT_MODEL.md)
- Test strategy: [`TEST_STRATEGY.md`](TEST_STRATEGY.md)
- Operability: [`OPERABILITY.md`](OPERABILITY.md)
- Compliance traceability: [`COMPLIANCE_TRACEABILITY.md`](COMPLIANCE_TRACEABILITY.md)
- Product/engineering traceability: [`TRACEABILITY.md`](TRACEABILITY.md)
- Documentation audit: [`DOCUMENTATION_AUDIT.md`](DOCUMENTATION_AUDIT.md)
- ADR index: [`../adr/README.md`](../adr/README.md)
- Standards and research: [`../doctoring/REFERENCES.md`](../doctoring/REFERENCES.md)
