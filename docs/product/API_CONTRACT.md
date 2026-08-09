# EgressWeave Public API Contract

Status: Proposed documentation baseline for **IMPLEMENTED-ON-PROTECTED-MAIN** public behavior. Exact exported symbols and signatures remain governed by source and tests.

## 1. Contract principles

EgressWeave exposes policy and builder APIs, not a network service API. Public objects are provider-neutral and are designed to be composed by a host application without exposing transport internals as authorization inputs.

The root [`../../ARCHITECTURE.md`](../../ARCHITECTURE.md) remains implementation truth. This document defines the compatibility and behavioral meaning of the public surface.

## 2. Core public concepts

The protected-main API includes these public concepts and repository-tested equivalents:

- `EgressPolicy` — normalized immutable egress authority/method/resource policy.
- `TLSConfiguration` — explicit trust-store and client-identity policy.
- `EgressConnectionPoolPolicy` — finite total/idle pool policy.
- `EgressTimeoutPolicy` — finite phase timeout ceilings.
- `ValidatedEgressURL` — integrity-bound validated URL/address state, not a permanent capability.
- `EgressDecisionEvidence` — deterministic bounded evidence for an accepted decision.
- `EgressNotAllowedError` — stable public policy denial.
- `validate_egress_url(...)` and asynchronous validation equivalent.
- synchronous and asynchronous pinned-client builders.
- naruon integration adapter that translates host configuration into the same core policy/builder path.

A future **ACTIVE-PR** may add a versioned machine-readable decision-evidence schema. It is not part of protected-main API until merged.

## 3. Policy construction contract

Policy constructors accept trusted operator configuration and fail fast when configuration is structurally ambiguous or removes a required finite bound. Host code should construct policies during startup and reuse them rather than derive authority dynamically from untrusted request data.

Host and authority allowlists are exact after canonicalization. Wildcard-host authorization is not a compatibility promise.

## 4. Validation contract

Validation returns either a `ValidatedEgressURL`-equivalent accepted value or a stable denial. Acceptance binds normalized authority to a finite set of validated address candidates. Callers must not replace this object with a raw URL, raw DNS answer, or caller-supplied IP when constructing the guarded transport.

Validation can legitimately fail when policy changes between initial creation and use. Such revalidation is a security feature, not an availability regression.

## 5. Client builder contract

Guarded client builders:

- use the validated/policy path rather than ambient `HTTP_PROXY` or related environment settings;
- do not follow redirects automatically;
- preserve original hostname TLS identity while connecting to validated addresses;
- enforce current request/response and timeout/pool policy;
- must be closed deterministically by the host application.

The host owns retries at the business-operation level and must not fall back to an unguarded client after an EgressWeave denial.

## 6. Request contract

A request can be rejected before connection, before pool dispatch, during body consumption, or while cleaning up a rejected body. Public callers must treat those cases as one policy-denial family unless a documented public exception type says otherwise.

The library does not authorize path semantics, query meaning, request-body business content, credentials, users, or tenant permissions. A host must complete those checks independently.

## 7. Response contract

A response is caller-visible only after response metadata passes current safety checks. A body stream can still fail later if exact consumed bytes exceed `max_response_bytes` or violate another streaming invariant. Callers must therefore handle denial during iteration as well as request creation.

The package does not promise malware/content classification; resource and protocol validation are distinct from semantic content trust.

## 8. Error contract

Security rejection uses stable generic errors so resolver, transport, filesystem, parser, and cleanup internals do not become a side-channel. Error text is not intended as a structured machine protocol unless explicitly versioned as such.

Application logs should attach host-owned correlation identifiers outside the exception rather than concatenate sensitive URLs, bodies, credentials, or resolved addresses into the library error.

## 9. Evidence contract

`EgressDecisionEvidence` is an audit aid for an accepted policy decision. It is not:

- proof that the remote service is trustworthy;
- proof that an application request was business-authorized;
- a SOC 2 or CSAP certification artifact by itself;
- a durable audit store;
- build provenance unless the specific release-evidence mechanism explicitly establishes that property.

Hosts decide whether and how to persist evidence under their own access, retention, encryption, and tenant-isolation controls.

## 10. Versioning and compatibility

EgressWeave is pre-1.0. Security-tightening changes can reject inputs that were previously accepted when continued acceptance would violate the documented security boundary. Such changes require regression evidence, release notes, and compatibility assessment.

Routine additions should preserve existing public names and behavior. Removal/renaming of a public symbol requires explicit migration guidance and a versioning decision. Internal/private HTTPCore adapter details are not public compatibility promises.

## 11. Host integration responsibilities

The host application owns:

- path/query/body business authorization;
- credential issuance and OAuth/API-key scope validation;
- user/tenant authentication and authorization;
- durable persistence, audit retention, and encryption-at-rest;
- retry/idempotency semantics;
- service-level objectives and alerting;
- network/firewall/service-mesh controls;
- legal/privacy purpose limitation for payload data.

See [`OPERABILITY.md`](OPERABILITY.md), [`COMPLIANCE_TRACEABILITY.md`](COMPLIANCE_TRACEABILITY.md), and [`../architecture/ERD.md`](../architecture/ERD.md).

## 12. Change acceptance

A public API change is accepted only after focused test-first evidence, full supported-Python CI, exact 100% production statement/branch coverage, docstring checks, package acceptance, applicable security scans, current-head review, and required independent approval/branch protections have passed on the exact candidate head.
