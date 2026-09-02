# EgressWeave

[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/ContextualWisdomLab/EgressWeave)

**Provider-neutral outbound HTTP security for Python applications that need explicit egress authority instead of ambient network trust.**

EgressWeave turns an approved HTTPS destination and a small policy into a synchronous or asynchronous HTTPX client that keeps destination authority stable from URL validation through DNS resolution and connection establishment. It is designed for applications that must call external APIs without allowing SSRF, DNS rebinding, proxy inheritance, redirects, malformed framing, or unbounded network I/O to widen the approved network boundary.

It is a library, not a firewall or service mesh. Use it inside an application to make outbound HTTP decisions explicit, reviewable, and fail-closed; keep network-layer enforcement, tenant authorization, credentials, and business-level request policy in their owning systems.

## Why EgressWeave

| Need | EgressWeave contract |
| --- | --- |
| Call only approved remote services | Exact normalized `(hostname, port)` authority allowlists and positive HTTP-method policy |
| Resist DNS rebinding | Validate every resolved address, then connect only through the validated address set while preserving the approved hostname for TLS and HTTP authority |
| Avoid ambient routing surprises | Redirects are disabled, environment proxies are ignored, Unix-socket and caller-selected destination bypasses are refused |
| Bound network resource use | Finite DNS, timeout, request-body, response-body, target, header, pool and connection policies |
| Keep failures safe to expose | Policy denials use a stable public error contract instead of leaking resolver or transport internals |
| Support ordinary Python services | Synchronous and asynchronous clients with the same core security invariants |

The protected implementation currently supports Python 3.10–3.14 and uses pinned `httpx`, `httpcore`, and `idna` runtime dependencies.

## Publication status

The package metadata version is `0.3.0`, but this repository currently has no GitHub release. Release automation and package acceptance can establish that source is ready to publish; they do not establish that an artifact is already available.

A bare `pip install egressweave` command is authoritative only after the exact target version appears on a verified PyPI project page with its expected distributions and publication/provenance evidence. Until then, install from a reviewed source checkout and preserve the repository's hash-locked verification before promoting the package into another system.

## Quickstart

Install from a reviewed checkout before independently verified artifact publication:

```bash
python -m pip install .
```

Create an exact egress policy and a synchronous client:

```python
from egressweave import EgressPolicy, build_egress_sync_client

policy = EgressPolicy.from_hosts("api.example.com")
base_url, client = build_egress_sync_client(
    "https://api.example.com/v1",
    policy=policy,
)

with client:
    response = client.get(f"{base_url}/status")
```

Asynchronous applications use the same policy boundary:

```python
from egressweave import EgressPolicy, build_egress_http_client

policy = EgressPolicy.from_hosts(
    "api.example.com",
    allowed_methods={"GET", "HEAD"},
)
base_url, client = await build_egress_http_client(
    "https://api.example.com/v1",
    policy=policy,
)

async with client:
    response = await client.get(f"{base_url}/status")
```

When different hosts need different ports, enumerate the allowed authority pairs instead of granting their Cartesian product:

```python
policy = EgressPolicy.from_authorities(
    [
        ("api.example.com", 443),
        ("admin.example.com", 8443),
    ]
)
```

## Security model

EgressWeave protects the **outbound transport decision**. Its guarded clients reject destinations and request metadata that would make the approved authority ambiguous or broader than the configured policy.

The protected implementation includes these control families:

- **SSRF resistance:** private, loopback, link-local, reserved, multicast, unspecified, IP-literal, credential-bearing, malformed, and unauthorized destinations fail closed.
- **DNS-rebinding resistance:** all accepted address candidates are validated before use and bound to the approved authority through the pinned transport.
- **Exact origin control:** hostname, port, scheme and HTTP method remain explicit; `CONNECT` is never authorized.
- **TLS identity preservation:** validated address pinning does not replace the approved hostname used for TLS server identity and HTTP authority.
- **Request bounds:** request target, headers, body framing, actual streamed bytes, declared length and per-phase timeouts are finite and checked before or during dispatch.
- **Response bounds:** response headers, declared length, content coding and actual streamed bytes are bounded; guarded clients request identity encoding to avoid unbounded decompression through the normal path.
- **Connection-pool bounds:** pool fanout and idle retention are explicitly bounded through `EgressConnectionPoolPolicy`, while acquisition waits are bounded through `EgressTimeoutPolicy`.
- **Stable denial semantics:** rejected operations raise the public policy error rather than exposing dependency-private failure details as an oracle.
- **Bounded decision evidence:** accepted decisions can be projected into versioned evidence without treating payloads, credentials, paths, or resolved IP addresses as routine audit output.
- **Deny-all optional configuration:** a missing or blank optional base URL produces a client that cannot perform network I/O instead of silently falling back to unrestricted HTTP.

EgressWeave complements, rather than replaces, firewall/service-mesh egress policy, sandboxing, application authorization, OAuth/API-key scope, tenant policy, malware inspection, job-level cancellation and service-level operations.

See [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) and [`ARCHITECTURE.md`](ARCHITECTURE.md) for the detailed trust boundary and implementation evidence.

## Configure the boundary

The high-level policy surface is intentionally small:

```python
from egressweave import EgressPolicy, EgressTimeoutPolicy

timeouts = EgressTimeoutPolicy(
    connect_timeout_seconds=2,
    read_timeout_seconds=10,
    write_timeout_seconds=5,
    pool_timeout_seconds=1,
)

policy = EgressPolicy.from_hosts(
    "artifacts.example.com",
    allowed_methods={"GET", "HEAD", "PUT"},
    max_request_bytes=8 * 1024 * 1024,
    max_response_bytes=64 * 1024 * 1024,
    request_timeout_policy=timeouts,
)
```

Private trust stores and mutual TLS are configured through immutable `TLSConfiguration` rather than a shared mutable SSL context:

```python
from egressweave import EgressPolicy, TLSConfiguration, build_egress_sync_client

tls = TLSConfiguration(
    ca_file="/etc/company/private-ca.pem",
    include_default_trust_store=False,
    client_certificate_file="/etc/company/client.pem",
    client_private_key_file="/etc/company/client.key",
)

base_url, client = build_egress_sync_client(
    "https://api.example.com",
    policy=EgressPolicy.from_hosts("api.example.com"),
    tls_configuration=tls,
)
```

Local development requires explicit opt-in to both local addressing and the exact service port; production callers should not inherit that exception accidentally.

## Product boundary

EgressWeave owns the reusable in-process policy, validation, TLS, connection-pool, pinned-transport, and bounded decision-evidence contracts. A host such as `naruon` owns provider configuration, credentials, tenancy, business authorization, persistence, audit retention, deployment, and the adapter that translates host settings into an EgressWeave policy.

```text
Host application
    │ approved base URL + explicit policy
    ▼
EgressWeave
    ├─ URL / authority / method validation
    ├─ bounded DNS resolution + address validation
    ├─ TLS / pool / transport policy
    ├─ bounded sync or async HTTPX client
    └─ bounded decision-evidence projection
    │
    ▼
Approved remote service
```

The library does not own a durable database. It does not infer which provider or endpoint a tenant is entitled to call, and it does not treat a successful network connection as application-level authorization.

## Public API

| Symbol | Purpose |
| --- | --- |
| `EgressPolicy` | Immutable destination, method, DNS and resource policy |
| `EgressTimeoutPolicy` | Finite connect/read/write/pool timeout ceilings, including pool-acquisition wait |
| `EgressConnectionPoolPolicy` | Finite total/keep-alive connection capacity and keep-alive expiry |
| `TLSConfiguration` | Immutable trust-store and optional mutual-TLS configuration |
| `validate_egress_url(...)` / `validate_egress_url_details(...)` | Synchronously validate a URL and its pinnable address candidates |
| `validate_egress_url_async(...)` / `validate_egress_url_details_async(...)` | Asynchronously validate a URL and its pinnable address candidates |
| `build_egress_sync_client(...)` | Build a synchronous guarded HTTPX client |
| `build_egress_http_client(...)` | Build an asynchronous guarded HTTPX client |
| `build_pinned_https_client(...)` / `build_pinned_https_async_client(...)` | Build from an already validated destination |
| `ValidatedEgressURL` | Integrity-bound validated destination state |
| `EgressDecisionEvidence` / `build_egress_decision_evidence(...)` | Produce bounded, versioned accepted-decision evidence |
| `get_decision_evidence_json_schema()` / `DECISION_EVIDENCE_SCHEMA_VERSION` | Expose the machine-readable decision-evidence contract |
| `EgressNotAllowedError` | Stable public policy-denial error |

For exact arguments, invariants and pre-1.0 compatibility rules, use [`docs/product/API_CONTRACT.md`](docs/product/API_CONTRACT.md) rather than copying implementation details into a host integration.

## Verification

The repository requires 100% owned production statement and branch coverage and tests the package across Python 3.10, 3.11, 3.12, 3.13 and 3.14. CI also builds and verifies wheel/source distributions and smoke-tests the installed wheel outside the source tree.

Run the same hash-locked quality toolchain used by CI:

```bash
python -m pip install --require-hashes -r requirements-ci.txt
ruff check .
coverage run -m pytest -q
coverage report -m
python -m compileall -q src tests scripts
```

Release readiness and package-build evidence are not the same as publication evidence. Verify the exact released artifact and provenance before depending on a bare package-index install in production.

## Documentation

- [Product requirements](docs/product/PRD.md)
- [Technical requirements](docs/product/TRD.md)
- [Architecture](ARCHITECTURE.md)
- [UML and system flows](docs/architecture/UML.md)
- [ERD and persistence boundary](docs/architecture/ERD.md)
- [API contract](docs/product/API_CONTRACT.md)
- [Threat model](docs/THREAT_MODEL.md)
- [Test strategy](docs/product/TEST_STRATEGY.md)
- [Operability](docs/product/OPERABILITY.md)
- [Compliance traceability](docs/product/COMPLIANCE_TRACEABILITY.md)
- [Release, rollback and provenance](docs/product/RELEASE_PROVENANCE.md)
- [Product/engineering traceability](docs/product/TRACEABILITY.md)
- [ADR index](docs/adr/README.md)
- [Standards and research](docs/doctoring/REFERENCES.md)
- [Documentation home](docs/index.md)

Repository-maintenance automation is documented in [`docs/hourly-autonomous-maintenance.md`](docs/hourly-autonomous-maintenance.md); it is not part of the customer-facing runtime contract.

## Contributing and support

For a behavior change, keep the public API, architecture/ADR evidence, security invariants, tests and package metadata aligned. Do not weaken fail-closed behavior or coverage to make a change pass. Report security-sensitive findings through the repository's security process rather than publishing exploit details in a public issue.

For integration support, start with the API contract and architecture documents above. Host-specific provider credentials, tenancy, network perimeter and deployment policy remain the host owner's responsibility.

## License

EgressWeave original source is licensed under the **Apache License 2.0**. See [`LICENSE`](LICENSE). Third-party dependencies retain their own licenses; the root grant does not relicense them.
