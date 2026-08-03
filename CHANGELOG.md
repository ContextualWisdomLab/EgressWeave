# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Add a coordinated vulnerability-disclosure policy with supported-version and
  response expectations, plus a security model that defines protected assets,
  attacker capabilities, enforced invariants, trust boundaries, integration
  requirements, and explicit non-goals.
- Add `EgressPolicy.allowed_ports`, defaulting to the standard HTTPS port 443,
  with normalized integer or decimal-string configuration and explicit opt-in
  for alternate TLS and local-development ports.
- Add `EgressPolicy.allowed_methods` with a fail-closed default set for ordinary
  API operations and explicit opt-in for non-tunnelling extension methods.

### Fixed
- Canonicalize request-time Unicode hostnames with the same UTS #46 processing
  used during policy validation, so an internationalized URL remains equivalent
  to its validated ASCII A-label in both synchronous and asynchronous clients.
- Treat a directly supplied comma-separated `allowed_hosts` string as hostname
  configuration instead of iterating it character by character.
- Preserve explicit port zero during URL parsing so it is rejected by the port
  policy rather than being silently replaced by the scheme's default port.
- Apply `EgressPolicy.dns_timeout_seconds` consistently to synchronous and
  asynchronous validation. Synchronous callers no longer depend indefinitely
  on a stalled platform resolver, and invalid zero, negative, non-finite,
  boolean, or nonnumeric timeout configuration is rejected at construction.
- Align the public `egressweave.__version__` value with the package release
  metadata and add a regression check that prevents future runtime/package
  version drift.

### Security
- Canonicalize trusted allowlist entries and candidate URL hostnames with UTS #46
  non-transitional IDNA processing and STD3 rules before comparison, DNS lookup,
  TLS SNI, or HTTP authority construction. Valid Unicode names now share one
  lowercase ASCII A-label identity, while malformed labels, invalid A-labels,
  empty labels, disallowed characters, and DNS length violations fail at policy
  construction instead of surfacing later at resolver or transport boundaries.
- Require `allow_local` to be an actual boolean. Truthy strings, integers, and
  other ambiguous configuration values now fail at policy construction instead
  of accidentally enabling access to loopback, RFC 1918, or RFC 4193 targets.
- Enforce the positive destination-port allowlist during URL validation before
  DNS resolution in synchronous and asynchronous paths. URLs that name an
  unauthorized effective port now fail with the generic
  `EgressNotAllowedError`; malformed, boolean, zero, negative, and out-of-range
  trusted configuration fails at policy construction.
- Enforce the HTTP-method allowlist inside both pinned transports before network
  I/O. Methods outside the policy now fail with the generic
  `EgressNotAllowedError`, and `CONNECT` cannot be configured because its
  proxy-tunnel target would introduce a second, unvalidated authority channel.
- Reject unusable non-empty allowlist entries when `EgressPolicy` is
  constructed. Wildcards, URL or authority syntax, IP literals and legacy
  numeric IP forms, whitespace/control characters, and non-string entries now
  fail fast instead of creating a policy that can only fail on its first
  request.
- Bind HTTPX's low-level `sni_hostname` request extension to the already
  validated authority in both synchronous and asynchronous transports. A
  mismatched, malformed, or nontextual TLS server-name override now fails
  closed before the connection pool, preventing SNI from becoming an
  independent authority channel on shared network addresses.
- Bound concurrent DNS resolver workers and keep platform-specific resolver
  failures behind the generic `EgressNotAllowedError` boundary. Timed-out
  resolver work cannot grow unbounded under repeated validation attempts.
- Make synchronous and asynchronous client builders fail closed when the base
  URL is empty or absent. They now return a deny-all client instead of silently
  exposing an unrestricted HTTP transport, preventing optional or missing
  configuration from bypassing the egress policy.
- Add weekly Dependabot monitoring for Python runtime/test dependencies and
  SHA-pinned GitHub Actions so constrained transport internals and CI supply-chain
  changes are surfaced for normal review and validation.

## [0.2.0] - 2026-08-03

### Added
- Add `build_egress_sync_client` and `build_pinned_https_client` for blocking
  applications. The synchronous `httpx.Client` transport preserves the same
  exact-host allowlist, address pinning, per-connect address revalidation,
  authority-drift rejection, proxy/redirect isolation, and Unix-socket refusal
  as the asynchronous transport, while retrying validated addresses within one
  caller-supplied connection-timeout budget.

### Security
- Isolate autonomous maintenance across credential-separated runners. A
  protected guard now rejects out-of-bound patch metadata and files, while
  modified source and tests execute only in an offline, non-root,
  capability-free, read-only verifier container built from trusted base
  dependencies before the patch is applied. The publisher never executes
  modified package code before obtaining its external write identity. Workflow
  tokens default to read-only and elevate only per job, while CI and autonomous
  verification install an explicit, SHA-256-locked dependency set.
- Make `ValidatedEgressURL` construction factory-only and attach a process-local
  integrity signature to every issued result. Pinned transports reject forged
  objects and any post-validation mutation, including replacement with another
  globally routable address, before rechecking scheme, allowlist, canonical
  URL/hostname/port agreement, address shape, and per-address scope without
  another DNS lookup.
- Reject every outbound request whose scheme, hostname, effective port, or
  embedded user information differs from the validated target before it reaches
  the connection pool. Requests can no longer be silently rewritten from an
  unvalidated absolute URL to the pinned host.
- Bind every `allow_local` exception to the original local hostname. Built-in
  local names accept loopback only, while allowlisted single-label container
  names accept loopback, RFC 1918 IPv4, or RFC 4193 IPv6 unique-local space.
  Dotted remote hosts cannot inherit the exception during DNS rebinding.
  Link-local, shared, documentation, benchmarking, unspecified, multicast, and
  reserved addresses remain blocked, including cloud metadata endpoints.

## [0.1.0] - 2026-07-12

### Added
- Initial release, extracted behaviour-preserving from the naruon control plane.
- `EgressPolicy` — injected egress host allowlist with an `allow_local` escape
  hatch and configurable DNS-resolution timeout.
- `validate_egress_url` / `validate_egress_url_details` and async variants —
  SSRF-safe URL validation (CWE-918) that resolves and checks **every** address.
- `build_egress_http_client` / `build_pinned_https_async_client` — DNS-pinned
  `httpx.AsyncClient` closing the validate-then-connect TOCTOU / DNS-rebinding
  gap (CWE-350), with redirects and environment proxies disabled.
- `EgressNotAllowedError` (a `ValueError` subclass) and `ValidatedEgressURL`.
- 35 tests covering URL rejection, address classification, the `allow_local`
  container case, DNS-to-private rejection, and transport pinning.
