# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
