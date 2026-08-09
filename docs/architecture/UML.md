# EgressWeave UML and behavior views

Status: **PRESENT-CURRENT** for protected-main runtime behavior unless a diagram is explicitly marked otherwise. Root [`../../ARCHITECTURE.md`](../../ARCHITECTURE.md) remains the authoritative implementation architecture.

These diagrams are review aids, not independent authority. If a diagram conflicts with code or root architecture, the code-current root architecture wins and this file must be corrected.

## 1. Core type and responsibility model

```mermaid
classDiagram
    class EgressPolicy {
      +allowed_authorities
      +allowed_methods
      +dns_timeout_seconds
      +max_request_bytes
      +max_response_bytes
      +request_timeout_policy
      +connection_pool_policy
    }
    class TLSConfiguration {
      +minimum_tls_version
      +ca_file
      +client_certificate_file
      +client_private_key_file
      +build_ssl_context()
    }
    class ValidatedEgressURL {
      +normalized_url
      +hostname
      +port
      +addresses
      +integrity_signature
    }
    class EgressTimeoutPolicy {
      +connect_timeout_seconds
      +read_timeout_seconds
      +write_timeout_seconds
      +pool_timeout_seconds
    }
    class EgressConnectionPoolPolicy {
      +max_connections
      +max_keepalive_connections
      +keepalive_expiry_seconds
    }
    class EgressDecisionEvidence {
      +schema_version
      +authority
      +allowed_methods
      +address_count
      +ipv4_address_count
      +ipv6_address_count
      +policy_fingerprint
      +decision_fingerprint
    }
    class SyncPinnedTransport
    class AsyncPinnedTransport
    class HostAdapter {
      <<host-owned>>
      +tenant selection
      +credential lifecycle
      +logging and metrics
      +policy construction
    }

    EgressPolicy *-- EgressTimeoutPolicy
    EgressPolicy *-- EgressConnectionPoolPolicy
    TLSConfiguration --> SyncPinnedTransport
    TLSConfiguration --> AsyncPinnedTransport
    EgressPolicy --> ValidatedEgressURL : validates candidate
    ValidatedEgressURL --> SyncPinnedTransport : pins destination
    ValidatedEgressURL --> AsyncPinnedTransport : pins destination
    ValidatedEgressURL --> EgressDecisionEvidence : revalidated evidence
    HostAdapter --> EgressPolicy : constructs
    HostAdapter --> TLSConfiguration : supplies
```

The host adapter is intentionally outside the core package. Provider registries, tenant authorization, credentials, persistence, queues, deployment and business-level path/body authorization remain host responsibilities.

## 2. Validation-to-request sequence

```mermaid
sequenceDiagram
    participant App as Application / naruon adapter
    participant Policy as EgressPolicy
    participant Validator as URL validation
    participant Resolver as OS resolver
    participant State as ValidatedEgressURL
    participant Transport as Pinned transport
    participant Peer as Remote TLS service

    App->>Policy: construct reviewed immutable policy
    App->>Validator: candidate HTTPS URL + policy
    Validator->>Policy: verify exact normalized authority and method policy
    Validator->>Resolver: resolve hostname under finite deadline
    Resolver-->>Validator: A / AAAA candidates
    Validator->>Validator: bound count; reject if any address class is disallowed
    Validator->>State: create integrity-bound validated state
    App->>Transport: build client from state + policy + TLS configuration
    Transport->>State: verify integrity, authority, address set and scope
    Transport->>Transport: validate method, target, headers, body and phase budgets
    Transport->>Peer: connect only to pinned revalidated address with original TLS identity
    Peer-->>Transport: response metadata and identity-coded body
    Transport->>Transport: enforce response field and max_response_bytes budgets
    Transport-->>App: caller-visible response or generic policy denial
```

## 3. Fail-closed request lifecycle

```mermaid
stateDiagram-v2
    [*] --> Candidate
    Candidate --> Denied: malformed URL / unauthorized authority / unsupported scheme
    Candidate --> Resolving: candidate accepted for DNS validation
    Resolving --> Denied: timeout / resolver error / unsafe address / excessive candidates
    Resolving --> Validated: all candidates accepted and state sealed
    Validated --> DispatchCheck: request enters pinned transport
    DispatchCheck --> Denied: authority / method / target / field / framing / body / timeout violation
    DispatchCheck --> Connecting: request remains within policy
    Connecting --> Denied: address revalidation or policy-bound connect failure
    Connecting --> Receiving: pinned TLS connection established
    Receiving --> Denied: response field / coding / declared-size / streamed-size violation
    Receiving --> Delivered: bounded response accepted
    Denied --> Cleanup: best-effort dependency cleanup
    Cleanup --> GenericError: attacker-controlled cleanup failure cannot replace denial
    GenericError --> [*]
    Delivered --> [*]
```

`KeyboardInterrupt`, `SystemExit`, `GeneratorExit`, and outer coordinator cancellation retain their separately tested control-flow semantics where applicable; ordinary dependency-controlled cleanup failures do not become a policy oracle.

## 4. Asynchronous connection-race behavior

```mermaid
sequenceDiagram
    participant T as Async pinned transport
    participant A as Candidate A task
    participant B as Candidate B task
    participant C as Cleanup coordinator

    T->>T: establish one absolute monotonic connection deadline
    T->>A: start first validated address
    T->>T: wait bounded stagger interval or immediate failure
    T->>B: start next validated address if needed
    alt first usable stream succeeds before deadline
        A-->>T: usable stream
        T->>C: cancel and await losing attempts
        C-->>T: cleanup complete or safely contained child failure
    else all candidates fail or deadline expires
        A-->>T: failure
        B-->>T: failure / cancelled
        T->>C: cancel/await pending attempts and close unusable streams
        C-->>T: normalized terminal denial
    end
```

The exact implementation details evolve through reviewed pull requests; protected-main code and tests determine which refinements are currently shipped.

## 5. Decision-evidence production

```mermaid
sequenceDiagram
    participant App as Host application
    participant State as ValidatedEgressURL
    participant Policy as EgressPolicy
    participant Evidence as EgressDecisionEvidence
    participant Store as Host-owned audit store

    App->>State: request evidence only after authorization and revalidation
    State->>Policy: bind authority-relevant policy facts
    State->>Evidence: emit canonical authority + aggregate address counts + fingerprints
    Evidence-->>App: detached data-minimized evidence
    opt host chooses durable audit storage
        App->>Store: persist under host tenant/access/retention policy
    end
```

The core does not emit raw credentials, bodies or resolved IP addresses in this evidence model.

## 6. Standalone and CWL modular boundary

```mermaid
classDiagram
    class EgressWeaveCore {
      <<owned here>>
      +policy validation
      +DNS validation/pinning
      +TLS construction
      +sync/async transports
      +resource bounds
      +decision evidence
    }
    class NaruonAdapter {
      <<host-owned>>
      +provider mapping
      +tenant selection
      +credentials
      +metrics/traces
    }
    class StandaloneServiceAdapter {
      <<host-owned>>
      +configuration
      +client lifecycle
      +application authorization
    }
    class InfrastructureControls {
      <<external defense in depth>>
      +firewall
      +service mesh
      +sandbox
      +KMS
    }

    NaruonAdapter --> EgressWeaveCore
    StandaloneServiceAdapter --> EgressWeaveCore
    InfrastructureControls ..> EgressWeaveCore : complements, does not replace
```

## 7. Automation authority separation

The repository has separate governance and product-development paths. Current protected-main implementation and active PRs must be distinguished in the product documentation fitness matrix.

```mermaid
sequenceDiagram
    participant Repo as EgressWeave repository
    participant Central as Organization PR maintenance
    participant Model as OpenCode + NVIDIA NIM
    participant Verify as Credential-free verifier
    participant Review as Independent review / repository gates

    Central->>Repo: inspect/fix/recheck PRs under central contract
    Model->>Repo: read protected source and propose bounded working-tree patch
    Model-->>Verify: untrusted patch handoff
    Verify->>Verify: revalidate base/diff and execute tests offline
    Verify-->>Review: exact patch evidence only
    Review->>Repo: normal review/check/merge authority remains separate
```

Repository-local autonomous model execution must not be treated as independent approval, security scanning, release authority or deployment authority.

## 8. Deployment view

```mermaid
flowchart LR
    subgraph Host[Host application / service boundary]
      CFG[Reviewed policy configuration]
      APP[Application or naruon adapter]
      EW[EgressWeave library]
      AUDIT[Host-owned audit / metrics]
    end
    DNS[Operating-system DNS resolver]
    NET[Operating-system network stack]
    REMOTE[Allowlisted remote TLS origin]
    FW[Firewall / service mesh defense in depth]

    CFG --> APP
    APP --> EW
    EW --> DNS
    EW --> NET
    NET --> FW --> REMOTE
    EW -. minimized evidence .-> APP --> AUDIT
```

EgressWeave is an in-process library, not an independently deployed proxy service on protected main.
