# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security
- Restrict the `allow_local` single-label-host escape hatch to loopback or
  private network space. Link-local, shared, unspecified, multicast, and
  reserved addresses remain blocked, including link-local cloud metadata
  endpoints.

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
