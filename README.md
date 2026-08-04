# egressweave

**SSRF- and DNS-rebinding-safe outbound HTTP for Python.**

`egressweave` validates an outbound URL against exact host-and-port
authority pairs and an HTTP-method allowlist, refuses any target that resolves
to a non-globally-routable address, and hands back a synchronous `httpx.Client` or
asynchronous `httpx.AsyncClient` whose every connection is *pinned* to the
validated addresses—rejecting authority drift and bounding every identity-coded
response body. An optional immutable TLS configuration adds private trust stores,
mutual-TLS client identities, and explicit protocol floors without allowing a
caller-owned mutable `SSLContext` to weaken the transport later.

It exists because the naive pattern—resolve, check the IP, then
`httpx.get(url)`—is unsafe. An attacker-controlled DNS answer can change between
the check and the connect (a TOCTOU / DNS-rebinding attack, CWE-350), while a
permissive URL, port, or method policy can reach unintended services (SSRF,
CWE-918), and even an allowlisted authority can exhaust resources with an
unbounded or compressed response (CWE-400).

## What it defends against

- **SSRF (CWE-918):** rejects private, loopback, link-local, reserved,
  multicast, unspecified, and otherwise non-global addresses; rejects embedded
  credentials, query/fragment, plaintext `http` to remote hosts, IP-literal
  hosts, backslash smuggling, and ASCII control characters.
- **Unexpected services on trusted hosts:** RFC 9110 defines an origin by its
  scheme, host, and port. EgressWeave defaults to port 443 only and requires
  explicit opt-in before an alternate TLS or local-development port is usable.
- **DNS rebinding / validate-then-connect TOCTOU (CWE-350):** resolves all
  addresses up front, validates each, and pins them into a custom transport
  that re-validates on every connect and refuses host/port drift.
- **Application-layer tunnelling:** a positive HTTP-method allowlist is enforced
  at the transport boundary. Common API methods are enabled by default, unusual
  methods require explicit opt-in, and `CONNECT` can never be authorized.
- **Mutable or weak TLS configuration:** configured integrations default to TLS
  1.3, allow only explicit TLS 1.2 compatibility, always verify certificates and
  hostnames, and create a fresh context from an immutable value object. Private
  trust and mTLS identities never bypass exact authority or DNS-pinning policy.
- **Unbounded response consumption (CWE-400):** both transports force
  `Accept-Encoding: identity`, reject body-bearing content-coded responses and
  unsafe declared lengths before returning a response, and count every
  transfer-decoded identity body byte. Chunked, close-delimited, missing-length,
  and dishonestly under-declared bodies cannot exceed the finite policy budget.
- **Bounded DNS resolution:** synchronous and asynchronous validation apply the
  same finite positive `dns_timeout_seconds` deadline. Resolver workers are
  concurrency-bounded and failures remain generic.
- **Exact egress allowlist:** only normalized `(hostname, port)` pairs explicitly
  present in the policy are reachable; wildcards and accidental cross-pair
  combinations are refused.
- Redirects are disabled and environment proxies ignored (`trust_env=False`),
  so a `302` cannot bounce a request to an unvalidated host, and Unix sockets
  are refused.
- **Fail-closed optional configuration:** an empty or absent base URL returns a
  deny-all client rather than an unrestricted fallback transport.

## Publication status

Release automation and package acceptance establish that a commit is ready
to publish; they do not establish that an artifact is already available.
A bare `pip install egressweave` command is authoritative only after the
exact version appears on a verified PyPI project page with its wheel, source
distribution, and publish-attestation evidence. Until then, install from a reviewed source checkout
and preserve the repository's hash-locked validation before promoting the
package into another system.

## Install

After the target version is verified on PyPI:

```bash
pip install egressweave
```

From a reviewed local checkout before the first public release:

```bash
python -m pip install .
```

## Quickstart

Synchronous applications:

```python
from egressweave import EgressPolicy, build_egress_sync_client

policy = EgressPolicy.from_hosts("api.openai.com, api.anthropic.com")

normalized_url, client = build_egress_sync_client(
    "https://api.openai.com/v1", policy=policy
)
with client:
    response = client.get(f"{normalized_url}/models")
```

Asynchronous applications:

```python
from egressweave import EgressPolicy, build_egress_http_client

policy = EgressPolicy.from_hosts("api.openai.com, api.anthropic.com")

normalized_url, client = await build_egress_http_client(
    "https://api.openai.com/v1", policy=policy
)
async with client:
    response = await client.get(f"{normalized_url}/models")
```

Narrow the method surface for each integration:

```python
read_only_policy = EgressPolicy.from_hosts(
    "api.example.com",
    allowed_methods={"GET", "HEAD"},
)
```

Authorize a non-standard HTTPS port only when the integration requires it:

```python
alternate_port_policy = EgressPolicy.from_hosts(
    "api.example.com",
    allowed_ports={443, 8443},
)
```

When several hosts use different ports, enumerate the exact authority pairs
instead of authorizing their Cartesian product:

```python
split_service_policy = EgressPolicy.from_authorities(
    [
        ("api.example.com", 443),
        ("admin.example.com", 8443),
    ]
)
```

Configure private trust and mutual TLS without passing a mutable context:

```python
import ssl

from egressweave import TLSConfiguration, build_egress_sync_client

enterprise_tls = TLSConfiguration(
    minimum_version=ssl.TLSVersion.TLSv1_3,
    ca_file="/run/secrets/enterprise-roots.pem",
    client_certificate_file="/run/secrets/client-chain.pem",
    client_private_key_file="/run/secrets/client-key.pem",
    client_private_key_password=lambda: read_client_key_password(),
)

normalized_url, client = build_egress_sync_client(
    "https://partner.example.com/v1",
    policy=EgressPolicy.from_hosts("partner.example.com"),
    tls_configuration=enterprise_tls,
)
```

`TLSConfiguration()` defaults to TLS 1.3, public trust, certificate validation,
and hostname verification. Existing peers that cannot yet negotiate TLS 1.3 can
explicitly select `ssl.TLSVersion.TLSv1_2`; that compatibility mode offers only
forward-secret ECDHE AEAD cipher suites. Set
`include_default_trust_store=False` only with an explicit `ca_file`, `ca_path`,
or `ca_data` value to create a private-only trust store. A client key or password
without `client_certificate_file` fails at startup.

Set an integration-specific identity response budget when the 16 MiB default is
not appropriate:

```python
artifact_policy = EgressPolicy.from_hosts(
    "artifacts.example.com",
    max_response_bytes=64 * 1024 * 1024,
)
```

The default authority projection uses port `{443}`. `from_hosts(...)` remains
concise when several hosts share one port or one host intentionally exposes
several ports. Supplying several hosts and several ports is rejected as
ambiguous; use `from_authorities(...)` to enumerate the exact permitted pairs.
Hostnames use the same UTS #46 normalization as URL validation, and ports may be
integers or ASCII decimal strings between 1 and 65535. Empty port segments are
ignored for environment-variable ergonomics. Port zero, booleans, floats,
malformed text, and out-of-range values fail fast. The exact normalized pair is
checked before DNS resolution.

The default method set is `GET`, `HEAD`, `POST`, `PUT`, `PATCH`, `DELETE`, and
`OPTIONS`. Method names are validated and normalized at policy construction.
Less common non-tunnelling methods such as `PROPFIND` require explicit opt-in.
`CONNECT` is always rejected, including when present in configuration.

The default response-body budget is 16 MiB. `max_response_bytes` accepts a
positive integer or an ASCII decimal string for environment-variable use. Zero,
negative, boolean, fractional, empty, signed, or malformed values fail at policy
construction. Pinned transports replace every caller compression preference
with `Accept-Encoding: identity`; a body-bearing response that still uses gzip,
deflate, Brotli, or another content coding is closed and rejected before HTTPX
can allocate decompressed output. Duplicate, malformed, or over-budget
`Content-Length` values fail before the response becomes caller-visible, and
every identity body stream is counted independently of framing metadata. On an
overrun, the underlying stream is closed and `EgressNotAllowedError` is raised.
Responses to `HEAD`, informational responses, `204`, and `304` remain bodyless
under RFC 9112 and do not treat representation metadata as transferred bytes.

Both builders fail closed when the supplied base URL is `None`, empty, or only
whitespace: they return `(None, client)`, but that client rejects every request
with `EgressNotAllowedError` before network I/O. This lets applications preserve
optional configuration shapes without silently bypassing the egress policy.

DNS resolution for both builders is bounded by `policy.dns_timeout_seconds`.
The value must be a finite positive number; invalid configuration is rejected
at policy construction rather than silently disabling the deadline.

Hostname allowlist configuration is also validated when `EgressPolicy` is
constructed. Supply bare hostnames only. Wildcards, URLs, credentials, ports,
paths, IP literals or legacy numeric IP forms, and embedded whitespace/control
characters raise `ValueError` before request handling begins; non-string entries
raise `TypeError`. Empty host segments remain ignored so comma-separated
environment variables may contain trailing separators.

Validate without building a client:

```python
from egressweave import EgressPolicy, validate_egress_url, EgressNotAllowedError

policy = EgressPolicy.from_hosts("api.openai.com")
try:
    url = validate_egress_url("https://api.openai.com/v1", policy=policy)
except EgressNotAllowedError:
    ...  # generic, non-leaking rejection
```

Local development requires both the local-address escape hatch and the exact
service port. For an Ollama-style container:

```python
policy = EgressPolicy.from_hosts(
    "ollama",
    allow_local=True,
    allowed_ports={11434},
)
```

## API

| Symbol | Purpose |
|---|---|
| `EgressPolicy` | Injected exact `(hostname, port)` authority, HTTP-method, DNS-timeout, local-address, and finite identity response-body resource policy; use `from_authorities(...)` when both host and port axes vary. |
| `TLSConfiguration` | Immutable TLS 1.3-by-default trust and mutual-TLS identity configuration; explicit TLS 1.2 compatibility remains verified and forward-secret. |
| `validate_egress_url` / `validate_egress_url_details` (+ `_async`) | Validate a URL and resolve pinnable addresses. |
| `build_egress_sync_client(url, *, policy, tls_configuration=None)` | Validate + build a synchronous DNS-pinned `httpx.Client`; empty URLs produce a deny-all client and all body-bearing responses are identity-coded and bounded. |
| `build_egress_http_client(url, *, policy, tls_configuration=None)` | Validate + build an asynchronous DNS-pinned `httpx.AsyncClient`; empty URLs produce a deny-all client and all body-bearing responses are identity-coded and bounded. |
| `build_pinned_https_client(validated, *, policy, tls_configuration=None)` | Build a bounded synchronous client from an already-validated URL. |
| `build_pinned_https_async_client(validated, *, policy, tls_configuration=None)` | Build a bounded asynchronous client from an already-validated URL. |
| `ValidatedEgressURL`, `EgressNotAllowedError` | Result type and typed failure (a `ValueError`). |

## Compatibility note

Exact authority-pair allowlisting, finite response-body limits, and identity-
only response coding are intentional pre-1.0 secure-default tightenings.
Applications with several hosts and several ports must migrate ambiguous
`from_hosts(...)` configuration to explicit `from_authorities(...)` pairs.
Integrations that legitimately consume more than 16 MiB per response must set a
larger, still-finite `max_response_bytes` value. Integrations that require
compressed response content need a separately reviewed client with a bounded
streaming decoder; EgressWeave does not silently accept compression.

Omitting `tls_configuration` preserves the existing verified HTTPX trust
behavior. Supplying it changes trust roots, client identity, and protocol floor
only; it cannot disable verification or alter authority, DNS pinning, proxy,
request, or response policy. New configured integrations should keep the TLS 1.3
default. Explicit TLS 1.2 is a migration exception for an existing peer.

## One source, multi use (OSMU)

`egressweave` is extracted, behaviour-preserving, from a production control
plane ([naruon](https://github.com/ContextualWisdomLab/naruon)), where it guards
every LLM-provider call. It is usable both as a standalone dependency and as a
git submodule. The original extraction replaced the app-specific settings
object with an injected `EgressPolicy`.

## Autonomous maintenance

Two hourly, credential-separated workflows keep the pull-request queue and the
product roadmap moving without bypassing normal governance:

- at minute `07`, the repository calls the organization-owned review-fix and
  merge schedulers to inspect feedback, recheck current-head evidence, update
  eligible branches, and merge only when every central gate permits it;
- at minute `37`, a bounded Codex maintainer runs only when there are zero open
  pull requests and implements one test-driven improvement.

The product workflow uses three fresh runners. The model job has read-only
GitHub permissions, no direct network access, and can emit only a guard-checked
patch. A second credential-free job builds trusted dependencies before applying
the patch and executes modified source only inside an offline, non-root,
capability-free, read-only verifier container. A third publisher rechecks the
sealed patch but never executes modified package code before obtaining an
external write identity. CI, security scans, independent reviews, branch
protection, and guarded auto-merge remain authoritative. See
[`docs/hourly-autonomous-maintenance.md`](docs/hourly-autonomous-maintenance.md)
for the complete control and configuration contract.

## Version compatibility

The pinned transports use a few `httpx` / `httpcore` internals, so those
libraries are constrained to `httpx>=0.28,<0.29` and `httpcore>=1.0,<2.0` and
exercised by the test suite. Bumping either requires re-verifying both the
synchronous and asynchronous transports.

## Research grounding

See [`docs/research`](docs/research/README.md): OWASP SSRF Prevention and
positive scheme/port/destination allowlisting, secure defaults / fail securely,
CWE-918, CWE-350 (DNS rebinding / TOCTOU), CWE-400 (uncontrolled resource
consumption), RFC 9110 (origin authority, content coding, and `CONNECT`), RFC
9112 (response body length), RFC 8305 (Happy Eyeballs-style concurrent connect
across asynchronously pinned addresses), and current BCP 195 TLS guidance. The
exact authority decision is specified in
[`exact-authority-pairs.md`](docs/research/exact-authority-pairs.md), enterprise
TLS and mTLS in [`tls-configuration.md`](docs/research/tls-configuration.md), and
response limits in
[`response-body-resource-limits.md`](docs/research/response-body-resource-limits.md).

## License

Apache-2.0. See [LICENSE](LICENSE).
