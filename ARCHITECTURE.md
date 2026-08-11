# EgressWeave architecture

## Purpose

EgressWeave is a provider-neutral Python security library for outbound HTTP. It
turns a reviewed egress policy into synchronous and asynchronous HTTPX clients
that fail closed when a URL, DNS result, request, transport extension, TLS
identity, response, or resource budget leaves the approved boundary.

The package is designed to work in two equally supported forms:

1. as a standalone dependency owned by one application; and
2. as a reusable security module inside naruon or another
   ContextualWisdomLab service.

Application settings, provider registries, tenant models, databases, logging
stacks, and deployment platforms remain outside the package. They are supplied
through immutable value objects and explicit builder arguments rather than read
from process-global state.

## Architectural principles

1. **Fail closed.** Indeterminate parsing, DNS, policy, integrity, framing,
   cleanup, or transport state becomes `EgressNotAllowedError` before unsafe
   network activity.
2. **Authorize complete identities.** Runtime destination authorization uses
   normalized `(hostname, port)` authority pairs. Security decisions must not be
   reconstructed from independent hostname and port projections.
3. **Validate once, pin through connect.** DNS answers are resolved, bounded,
   validated, integrity-protected, and rechecked immediately before every TCP
   connection.
4. **One authority channel.** URL authority, HTTP `Host`, TLS SNI, certificate
   verification identity, and socket destination remain bound to the reviewed
   target.
5. **Finite resources.** DNS candidates, connection-pool capacity, request
   target, request fields, request body, request phases, response fields, and
   response body all have positive finite policy limits.
6. **Provider neutrality.** No OpenAI, Anthropic, NVIDIA, cloud, service-mesh,
   or application-specific object is required by the runtime package.
7. **Dependency injection over ambient configuration.** Policies and TLS
   configuration are explicit immutable inputs. Environment proxy discovery,
   redirects, Unix sockets, and caller-selected destination IPs are disabled.
8. **Data-minimized diagnostics.** Runtime denials expose one generic message.
   Optional decision evidence records canonical authority and aggregate policy
   facts without paths, credentials, response data, or resolved IP addresses.
9. **Exact-head evidence.** CI, package acceptance, SAST, security scanning,
   reviews, and release evidence must describe the current pull-request head.
10. **Standalone and modular parity.** A security invariant added here must be
    evaluated for bidirectional porting to naruon without introducing naruon as
    a runtime dependency.

## Component map

```text
Application / naruon adapter
        |
        | EgressPolicy + optional TLSConfiguration
        v
Public client builders
        |
        +--> URL parser and policy validation
        |        |
        |        +--> IDNA canonicalization
        |        +--> exact authority and method checks
        |        +--> bounded DNS resolution
        |        +--> address classification
        |        +--> integrity-protected ValidatedEgressURL
        |
        +--> synchronous or asynchronous pinned transport
                 |
                 +--> request authority and TLS-SNI binding
                 +--> positive request-extension allowlist
                 +--> request target / field / body limits
                 +--> finite request-phase timeouts
                 +--> finite connection-pool policy
                 +--> per-connect address revalidation
                 +--> identity-only response coding
                 +--> response field / body limits
                 +--> generic denial and deterministic cleanup
```

### Policy layer

`EgressPolicy` is the single security-policy dependency. It owns normalized
allowlisted authorities, methods, local-development scope, DNS deadlines,
resource ceilings, request timeout policy, and connection-pool policy.
Construction is the trusted-configuration boundary: malformed values raise
`TypeError` or `ValueError` before a request is accepted.

Compatibility projections such as `allowed_hosts`, `allowed_ports`, and
`allowed_methods` are for configuration and operator inspection. Authorization
code must use complete policy identities rather than combining projections.

### Validation layer

The validation layer parses one candidate URL and rejects credentials,
fragments, unsupported schemes, IP literals, control characters, ambiguous
ports, unauthorized authorities, and unsafe local-development targets. It
resolves every address under a finite deadline and bounded worker pool, rejects
the entire destination if any result falls outside the allowed address class,
and returns an integrity-protected `ValidatedEgressURL`.

Validation does not authorize an application operation, credential, path, body,
or tenant. Those remain responsibilities of the embedding service.

### Transport layer

The synchronous and asynchronous transports consume only validated state and an
immutable policy. They build fresh TLS contexts, use finite connection pools,
revalidate each pinned address before connection, and prevent authority drift at
the last boundary before HTTPCore.

Request processing occurs in this order:

1. verify canonical method and request authority;
2. apply a positive request-extension allowlist: only reviewed `timeout`
   metadata and the validated `sni_hostname` identity channel may continue,
   while `target`, `trace`, non-string keys, and unknown future extensions fail
   closed before pool dispatch;
3. bind TLS SNI to the already validated hostname;
4. validate and rewrite outbound fields;
5. enforce the exact percent-encoded target budget;
6. enforce final request-field count and byte budgets;
7. enforce declared and streamed request-body budgets;
8. bind finite connect, read, write, and pool-acquisition timeouts; and
9. dispatch to HTTPCore through the pinned network backend.

Response processing occurs before a caller-visible HTTPX response is returned:

1. enforce decoded field count and byte budgets;
2. require identity content coding for body-bearing responses;
3. reject unsafe declared lengths; and
4. wrap the body stream with a cumulative byte budget.

Denied request and response streams are closed. Cleanup failures are suppressed
behind a fresh generic policy error so attacker-controlled exception text does
not cross the trust boundary.

### TLS layer

`TLSConfiguration` creates a fresh SSL context per pinned transport. TLS 1.3 is
the default. Explicit TLS 1.2 compatibility is restricted to reviewed
forward-secret AEAD suites. Integrations may add private trust roots, isolate a
private trust store, or supply an mTLS client identity without sharing a mutable
`SSLContext` between tenants or clients.

### Decision-evidence layer

`EgressDecisionEvidence` is an opt-in audit artifact for an already authorized
and revalidated destination. It contains canonical authority, authority-relevant
method policy, aggregate address-family counts, and deterministic policy and
decision fingerprints. Fingerprints detect configuration drift; they are not
cryptographic proof against arbitrary in-process code execution.

## Trust boundaries

| Boundary | Trusted input | Untrusted input | Required behavior |
|---|---|---|---|
| Policy construction | reviewed application configuration | malformed deployment values | reject before request handling |
| URL validation | immutable policy | URL text and DNS answers | validate every identity and address |
| Validated state | package-local integrity key | forged or mutated result objects | reject before transport construction |
| Request dispatch | validated authority and policy | method, path, fields, body, extensions | canonicalize only reviewed fields; otherwise deny |
| TCP connect | pinned address set | connection attempts and platform failures | revalidate every address; never re-resolve by hostname |
| TLS | fresh context and validated hostname | peer certificate and caller SNI override | bind identity; deny mismatch |
| Response delivery | finite response policy | peer fields, framing, coding, and body | bound and validate before exposure |
| Audit export | revalidated decision | paths, credentials, IPs, response data | omit sensitive request and peer data |

Arbitrary code execution inside the embedding Python process is outside the
security model. Network firewalls, service-mesh policies, sandboxing, tenant
authorization, credential scope, path authorization, malware scanning, and data
loss prevention remain defense-in-depth controls rather than substitutes for
EgressWeave.

## Integration contracts

### Standalone application

A standalone service constructs one narrow policy per trust domain, builds one
client per validated origin, reuses that client within the configured pool
capacity, and closes it deterministically. It must not fall back to a generic
HTTPX client after a denial.

### naruon and CWL services

An adapter may translate an application settings model or provider registry into
`EgressPolicy` and `TLSConfiguration`. The adapter owns provider names, tenant
selection, credentials, metrics, traces, and lifecycle management. The core
package must not import the adapter or any application settings module.

Security fixes should be ported in both directions using behavior-level tests:

```text
EgressWeave invariant
        -> standalone regression test
        -> naruon adapter/integration regression test
        -> exact-head CI and security gates in both repositories
```

### Microservice environments

Container aliases and loopback names require explicit hostname, port, and
`allow_local=True` configuration. Enabling local addresses changes only the
permitted address class; it never creates an implicit hostname or port grant.
Production policies should normally retain global-address-only behavior.

### Observability

The embedding service may emit metrics for decision outcome, latency, timeout
phase, pool saturation, address-family counts, and generic denial category only
when the category cannot reveal protected network topology. Raw URLs,
credentials, request bodies, response bodies, and resolved addresses must not be
included in default logs or metrics.

## Concurrency and capacity

`EgressConnectionPoolPolicy` bounds total connections, retained idle
connections, and keepalive lifetime. These are per-client limits. Applications
must additionally bound the number of clients, queued jobs, tenant concurrency,
retry attempts, and total workflow deadlines. Per-request and per-client limits
do not by themselves impose a process-wide resource ceiling.

The asynchronous pinned backend staggers validated address attempts rather than
launching every candidate simultaneously. Losing tasks are cancelled and
awaited after a connection succeeds.

## Error model

- Invalid trusted configuration: `TypeError` or `ValueError` during startup.
- Rejected or indeterminate egress decision: generic
  `EgressNotAllowedError("egress URL is not allowed")`.
- Ordinary HTTPX/HTTPCore network failures after a permitted dispatch: mapped to
  the corresponding HTTPX transport exception.
- Caller- or peer-controlled cleanup errors during a policy denial: suppressed
  and replaced by a fresh generic policy error without cause or context.

## Quality and release gates

A change is mergeable only when its exact current head satisfies:

- Python 3.10–3.13 CI;
- Ruff and compile validation;
- production statement and branch coverage of 100%;
- useful docstrings on every shipped module, class, function, and method;
- deterministic offline security tests for affected sync and async paths;
- wheel and source-distribution package acceptance;
- installed-wheel smoke testing outside the source tree;
- SAST, dependency, and security checks;
- resolved actionable review feedback; and
- repository branch-protection policy.

Releases additionally require a dated CHANGELOG section, matching package and
runtime versions, immutable tag-to-main binding, reproducible package evidence,
checksums, OIDC Trusted Publishing, provenance/attestations, and successful
publication before the GitHub Release is made public.

## Repository automation

- At minute `07` each hour, the repository invokes organization-owned reusable
  workflows for review-feedback repair, current-head rechecks, branch updates,
  and guarded direct or automatic merge. The existing review-agent identity and
  inherited secret contract are preserved.
- At minute `37` each hour, product development runs only when no pull request is
  open. It uses a pinned OpenCode CLI with `NVIDIA_NIM_API_KEY`, not
  `COPILOT_GITHUB_TOKEN`. Model execution, credential-free reverification, and
  publication use separate runners and permissions.

Neither automation path may treat queued, pending, cancelled, stale-head, or
previous-head evidence as success.

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

W3C. (2025). *Web application security best practices*. World Wide Web
Consortium. https://www.w3.org/TR/webappsec-best-practices/
