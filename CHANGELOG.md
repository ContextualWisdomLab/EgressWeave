# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Add deterministic IDNA hostname canonicalization using UTS #46
  non-transitional processing and STD3 rules; Unicode policy entries and URLs
  converge on one ASCII A-label before comparison, DNS resolution, and pinning.
- Add an explicit TCP destination-port allowlist to `EgressPolicy`; the default
  permits standard HTTP/HTTPS ports, while custom and local service ports must
  be opted in.
- Add `build_optional_egress_http_client`, which represents an absent optional
  endpoint as `(None, None)` rather than an unrestricted HTTP client.
- Ship the PEP 561 `py.typed` marker and enforce complete source docstrings.
- Enforce 100% line and branch coverage across every supported Python version.

### Changed
- Make `build_egress_http_client` fail closed for empty or absent URLs instead
  of returning an unrestricted fallback client.
- Cancel superseded CI runs for the same pull request to reduce runner backlog.

### Security
- Reject invalid IDNA labels and non-string policy hosts at construction, and
  surface malformed Unicode URL hosts only through the generic egress denial.
- Reject URLs whose effective destination port is not explicitly allowlisted,
  preventing an approved hostname from being used as a proxy to unexpected
  services on alternate ports.
- Reject reserved explicit port `0` instead of silently rewriting it to the
  scheme default, and reject non-positive, non-finite, boolean, or non-numeric
  DNS timeout configuration when constructing an `EgressPolicy`.
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
