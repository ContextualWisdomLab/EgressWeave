# EgressWeave System Architecture Views

Status: Proposed supplementary views of **IMPLEMENTED-ON-PROTECTED-MAIN** behavior. Root [`../../ARCHITECTURE.md`](../../ARCHITECTURE.md) remains authoritative when this document and implementation disagree.

## 1. System context

EgressWeave is embedded inside a host application. It constrains outbound HTTP authority but does not own business authorization, durable persistence, tenant identity, or network perimeter enforcement.

```mermaid
flowchart LR
    user_code[Host application code] --> host_auth[Host business authorization]
    host_auth --> egress_policy[EgressPolicy and immutable runtime policy]
    egress_policy --> validation[URL and DNS validation]
    validation --> validated_state[Integrity-bound ValidatedEgressURL]
    validated_state --> transport[Pinned sync or async transport]
    tls_policy[TLSConfiguration] --> transport
    timeout_policy[EgressTimeoutPolicy] --> transport
    pool_policy[EgressConnectionPoolPolicy] --> transport
    transport --> remote_service[Approved remote HTTPS service]
    transport --> evidence[EgressDecisionEvidence]
    evidence --> host_audit[Host-owned optional audit/telemetry]
    network_control[Firewall / service mesh / cloud egress] -. defense in depth .-> remote_service
```

## 2. Authority-preserving request path

```mermaid
flowchart TD
    raw_url[Candidate HTTPS URL] --> parse[Parse and canonicalize]
    parse --> authority[Authorize normalized hostname + port + method]
    authority --> dns[Resolve DNS with finite timeout]
    dns --> classify[Deduplicate, classify, and bound every address]
    classify --> state[Create integrity-bound validated state]
    state --> revalidate[Revalidate against current policy]
    revalidate --> tcp[Connect to one validated IP]
    tcp --> tls[TLS handshake using approved hostname identity]
    tls --> request_checks[Target + headers + framing + body + timeout/pool checks]
    request_checks --> http_dispatch[HTTPCore/HTTPX dispatch]
    http_dispatch --> response_checks[Response headers + encoding + body-byte checks]
    response_checks --> caller[Caller-visible response]

    parse -->|reject| deny[Stable EgressNotAllowedError]
    authority -->|reject| deny
    classify -->|reject| deny
    revalidate -->|reject| deny
    request_checks -->|reject| deny
    response_checks -->|reject| deny
```

The validated IP is a connection target, not a new logical authority. SNI, certificate hostname validation, and HTTP authority continue to use the normalized approved hostname.

## 3. Component ownership

| Component | Core responsibility | Explicitly not owned |
|---|---|---|
| Policy normalization | Exact host/authority, method, local-address and finite-resource configuration | User/tenant/business-object authorization |
| URL validation | HTTPS syntax, canonical hostname, authority/method gating | Business meaning of paths/query/body |
| DNS validation | Finite resolution, every-candidate classification, candidate cap | DNS infrastructure availability/SLA |
| Validated state | Bind accepted authority/addresses/policy identity | Permanent capability semantics |
| Pinned transport | Validated-IP TCP with hostname TLS/HTTP identity | Arbitrary proxies, Unix sockets, redirects |
| Request safety | Method/header/target/framing/body budgets | Credential scope or payload meaning |
| Response safety | Header/body/content-coding resource boundary | Malware/content classification |
| TLS configuration | Trust roots, client identity, protocol policy | Enterprise CA lifecycle/KMS |
| Decision evidence | Bounded deterministic accepted-decision facts | Durable audit database or certification claim |
| naruon adapter | Translate host config into core objects | A second transport/security implementation |

## 4. Standalone and naruon deployment views

```mermaid
flowchart TB
    subgraph standalone[Standalone application]
        app_one[Application] --> builder_one[EgressWeave builder]
        builder_one --> client_one[Guarded HTTPX client]
    end

    subgraph naruon_host[naruon or CWL service]
        naruon_config[Host configuration] --> adapter[naruon integration adapter]
        adapter --> builder_two[Same EgressWeave builder]
        builder_two --> client_two[Guarded HTTPX client]
    end

    client_one --> internet[Approved HTTPS authorities]
    client_two --> internet
```

The modularity invariant is that host adapters reuse the same policy/validation/transport layer. Cross-repository integration must not create hidden coupling to a mutable branch or duplicate the core SSRF policy.

## 5. Runtime trust boundaries

### Trusted startup configuration

Allowed authorities, methods, local-address decisions, TLS configuration, finite timeout/pool/resource policies, and host integration configuration must come from a trusted deployment/control plane.

### Untrusted runtime inputs

URLs, DNS answers, HTTP metadata, streaming chunks, remote responses, dependency exceptions, and cleanup behavior are treated as untrusted. They may cause a stable denial but may not widen destination authority.

### Host-owned sensitive context

Credentials, application payloads, users, tenants, business authorization, detailed logs, and persistence remain outside the core evidence model.

## 6. Denial and cleanup architecture

Once policy denial is decided, cleanup is best-effort and subordinate to the public denial contract. Dependency-controlled cleanup failure must not replace a security denial. Interpreter/process control-flow exceptions and caller/coordinator cancellation remain explicitly separated from dependency-child failure according to the implemented sync/async contracts.

See [`UML.md`](UML.md) for sequence/state views and [`../product/TEST_STRATEGY.md`](../product/TEST_STRATEGY.md) for regression requirements.

## 7. Development and release authority

Repository automation is intentionally separated from runtime product authority. Protected-main behavior is determined by merged source plus required checks/reviews. Product-development model execution, PR maintenance/review, release publication, and organization control-plane workflows may use different identities and permissions; success in one lane must not be reinterpreted as authority in another.

Automation changes that exist only on an **ACTIVE-PR** are not part of this current system architecture until protected merge and operational acceptance.

## 8. Persistence boundary

EgressWeave core does not persist policies, requests, responses, credentials, decision evidence, or audit events. See [`ERD.md`](ERD.md) for the explicit no-owned-database decision and a NON-NORMATIVE host integration model.
