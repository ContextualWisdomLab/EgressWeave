# ADR 0001: Security boundaries and modular integration

- **Status:** Accepted
- **Date:** 2026-08-05
- **Decision owners:** ContextualWisdomLab maintainers

## Context

EgressWeave originated as an outbound-provider guard in naruon and now also
ships as a standalone Python package. The library must remain independently
useful while supporting import into naruon and other CWL services. This creates
an architectural risk: application settings, provider types, credentials,
tenants, logging, or deployment assumptions could leak into the package and
make security behavior inconsistent across integrations.

A second risk is fragmented authorization. Hostname, port, method, TLS server
name, HTTP `Host`, socket address, request target, proxy behavior, and resource
budgets are different protocol channels. Checking some channels independently
can accidentally authorize combinations that nobody reviewed.

A third risk is operational overclaiming. A security library can pass unit tests
while its current pull-request head, package artifact, or release provenance is
not the object that was actually reviewed and verified.

## Decision

EgressWeave will use the following contracts.

### 1. Provider-neutral core

The runtime package owns URL validation, normalized egress policy, DNS
resolution and pinning, synchronous and asynchronous transports, TLS context
construction, finite resource controls, integrity-protected validation state,
and data-minimized decision evidence.

It will not own provider registries, API credentials, tenant selection,
application settings, persistence, job queues, logs, metrics backends, service-
mesh policy, or cloud SDKs. Applications translate those concerns into immutable
EgressWeave value objects through adapters.

### 2. Complete identity authorization

Destination authorization uses complete normalized authority identities. URL
authority, forwarded `Host`, TLS SNI, certificate verification hostname, and
socket destination remain bound to the same validated state. Compatibility
projections are not independent authorization lists.

HTTP methods are checked at the transport boundary, `CONNECT` is permanently
rejected, redirects and environment proxies remain disabled, and callers cannot
supply alternate destination IPs, Unix sockets, or absolute-form proxy targets.

### 3. Fail-closed finite execution

Every indeterminate policy decision is a denial. DNS candidates, DNS worker
concurrency, connection-pool capacity, request target, request fields, request
body, request phases, response fields, and response body have positive finite
limits. Cleanup failures during a denial cannot replace the generic policy error
or disclose attacker-controlled exception text.

### 4. Standalone and modular parity

The standalone API is the source of truth for security behavior. naruon and
other CWL services integrate through narrow adapters and retain application-
specific authorization, lifecycle, observability, and credential management.
Security fixes are evaluated for bidirectional porting with deterministic tests,
without creating a runtime dependency from EgressWeave back to naruon.

### 5. Evidence-bound delivery

A pull request is not mergeable until the exact current head satisfies required
CI, 100% production statement and branch coverage, docstring contracts, package
acceptance, SAST, security checks, review resolution, and branch protection.
Queued, pending, cancelled, stale-head, previous-head, or synthetic-merge-only
evidence is not substituted for current-head evidence.

A release additionally requires version and dated CHANGELOG agreement,
immutable tag-to-protected-main binding, checksums, reproducible build evidence,
OIDC Trusted Publishing, provenance/attestations, and successful package
publication before a public GitHub Release.

### 6. Credential-separated automation

The organization-owned review scheduler retains its existing identity and
inherited-secret contract. Autonomous product development uses a pinned
OpenCode CLI with `NVIDIA_NIM_API_KEY`, never `COPILOT_GITHUB_TOKEN`. Model
execution cannot directly publish changes. A separate credential-free lane
reverifies a bounded patch and emits only a short-lived digest-bound handoff.
No repository-local product-development job obtains repository-write authority
or creates or publishes a branch or pull request. Any later promotion is
external to the product workflow, independently reviewed, credential-separated,
and exact-tree verified before repository write.

## Alternatives considered

### Application-specific package

Keeping naruon settings and provider models in the package would reduce adapter
code but couple releases, tenants, and security behavior to one application. It
was rejected because it weakens standalone use and makes fixes harder to reuse.

### Network-only controls

Relying exclusively on firewall, proxy, or service-mesh egress rules would not
protect application-layer authority drift, HTTP method tunnelling, malformed
framing, excessive metadata, response decompression, or missing optional
configuration. Network controls remain defense in depth rather than the sole
boundary.

### Validation followed by a generic HTTP client

Resolving and checking a hostname before calling a generic client leaves a
validate-then-connect DNS rebinding window and permits environment proxies,
redirects, or alternate authority channels. It was rejected in favor of pinned
transports.

### Global ambient configuration

Reading security settings from process globals or environment variables inside
the package would make tests and tenant isolation less reliable. It was
rejected in favor of immutable explicit dependencies created during application
startup.

## Consequences

### Positive

- Security behavior is portable across standalone and CWL deployments.
- Application adapters stay small and reviewable.
- Authority, TLS, DNS, framing, and resource invariants are tested in one place.
- Current-head and release evidence support procurement and acquisition due
  diligence.
- Autonomous work can continue without granting model execution a publishing
  credential.

### Costs

- Applications must construct policies and lifecycle-manage clients explicitly.
- Some HTTPX and HTTPCore private APIs remain version-constrained and require
  compatibility tests.
- Secure defaults can tighten pre-1.0 behavior and require explicit migration.
- Process-wide quotas, tenant authorization, and network enforcement still need
  application and infrastructure controls.

## Validation

This ADR is supported by:

- the invariant list in `AGENTS.md`;
- the component and trust-boundary model in `ARCHITECTURE.md`;
- the threat model in `docs/security-model.md`;
- exact-head CI and package-acceptance workflows;
- hourly review/merge and OpenCode product-development workflows; and
- protocol-specific APA 7th research notes under `docs/research/`.

## References

Fielding, R. T., Nottingham, M., & Reschke, J. (2022). *HTTP semantics*
(RFC 9110). RFC Editor. https://doi.org/10.17487/RFC9110

Nottingham, M., & Thomson, M. (2024). *Building protocols with HTTP*
(RFC 9205). RFC Editor. https://doi.org/10.17487/RFC9205

OWASP Foundation. (n.d.). *Authorization cheat sheet*. OWASP Cheat Sheet
Series. Retrieved August 5, 2026, from
https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html

OWASP Foundation. (n.d.). *Server side request forgery prevention cheat sheet*.
OWASP Cheat Sheet Series. Retrieved August 5, 2026, from
https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html
