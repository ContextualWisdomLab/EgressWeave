# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Document the hourly product-development maintainer's bounded root-cause
  analysis and operational feasibility loop, including canonical prompt and
  control-plane incident handling.
- Add canonical `SOURCE_IDENTITY.json` evidence that seals the exact repository
  and 40-character protected-main source commit inside the checksummed release
  set. Handoff manifests now use format version 2 and include both source-identity
  and checksum-file digests for independent credential-bound revalidation.
- Add a shipped, credential-free sealed release-evidence verifier that accepts
  only the exact wheel, source distribution, paired CycloneDX 1.7 SBOMs, and
  canonical `SHA256SUMS`; independently recomputes content-bound UUIDv5 and
  root-artifact bindings; applies finite evidence-size limits; and emits a
  deterministic repository-and-source-bound manifest for a credential-separated
  organization attestation workflow.
- Add a deterministic, content-bound RFC 4122 UUID version 5 `serialNumber`
  adapter for CycloneDX 1.7 release evidence, satisfying the reviewed
  `actions/attest` CycloneDX parser without timestamps, random identifiers, or
  branch-local changes to credential-bearing release workflows.
- Add deterministic CycloneDX 1.7 SBOM generation that binds each canonical
  wheel and source distribution to its exact SHA-256 and a reviewed, hash-pinned
  runtime dependency graph. Protected attestation integration remains separate
  from branch-local workflows that contain release write credentials.
- Add immutable provider-neutral `EgressConnectionPoolPolicy` with finite
  total-connection, retained-idle-connection, and idle-expiry limits shared by
  synchronous and asynchronous pinned transports. Both public policy
  constructors expose the same stable dependency-injection contract.
- Add immutable provider-neutral `TLSConfiguration` dependency injection for
  private trust stores and mutual-TLS client identities across synchronous and
  asynchronous DNS-pinned builders. TLS 1.3 is the default; explicit TLS 1.2
  compatibility remains restricted to forward-secret ECDHE suites.
- Add explicit, deterministic `EgressDecisionEvidence` for successful egress
  decisions. Evidence revalidates signed state and records canonical authority,
  method policy, aggregate address-family counts, and correlation fingerprints
  without exposing request paths or resolved IP addresses.
- Add `EgressPolicy.max_request_bytes` with a secure finite 16 MiB default,
  positive integer or ASCII decimal-string configuration, and fail-fast
  rejection of values that could silently remove the outbound resource bound.
- Add `EgressPolicy.max_request_header_fields` and
  `EgressPolicy.max_request_header_bytes` with finite defaults of 100 fields and
  64 KiB of final field-name and field-value bytes. Both public policy
  constructors accept positive integers or ASCII decimal strings and reject
  ambiguous or non-positive configuration before network I/O.
- Add `EgressPolicy.max_request_target_bytes` with a finite 8 KiB default. Both
  public policy constructors accept positive integers or ASCII decimal strings
  and reject ambiguous or non-positive configuration during trusted startup.
- Add `EgressPolicy.max_response_header_fields` and
  `EgressPolicy.max_response_header_bytes` with finite defaults of 100 fields
  and 64 KiB of decoded field-name and field-value bytes. Both public policy
  constructors accept positive integers or ASCII decimal strings and reject
  ambiguous or non-positive configuration before network I/O.

### Fixed
- Correct the buyer-facing autonomous-maintainer identity from the retired Codex
  wording to the pinned OpenCode execution path backed by `NVIDIA_NIM_API_KEY`,
  without changing the centrally managed review-agent credential contract.
- Require the hourly product-development maintainer to perform exact-evidence
  root-cause analysis and operational feasibility validation before selecting,
  abandoning, or escalating a remediation.
- Load the hourly product-development maintainer from one canonical prompt file
  with a 12 KiB control-plane budget instead of an inline YAML heredoc. Generic
  scheduler failures are treated as resumable control-plane incidents; prompt
  repair alone is not completion, and transient connector/provider errors do not
  disable the recurring loop.

### Security
- Require the request timeout policy to use the exact `EgressTimeoutPolicy` type
  during trusted construction. Timeout-policy subclasses are rejected before
  transport dispatch can dynamically invoke an overridden `as_httpcore_timeout()`,
  preserving the reviewed finite ceilings as the authoritative configuration.
- Pin the credential-free verifier to a reviewed Python 3.13
  `python@sha256:<64-hex>` digest, validate it before Docker execution, and
  remove mutable-tag and `RepoDigests` promotion from the verifier boundary.
- Enforce one hard connection deadline across every staggered asynchronous
  attempt and coordinator wait, and make the synchronous pinned transport refuse
  a TCP attempt when the zero remaining connection budget is already exhausted.
  Deadline exhaustion keeps dependency-specific failures and cleanup outcomes
  behind the existing generic egress denial while preserving caller cancellation.
- Restrict low-level HTTPCore request extensions to the reviewed finite `timeout`
  metadata and validated `sni_hostname` identity channel. `trace`, `target`,
  unknown extension keys, non-string keys, and hostile extension mappings now
  fail closed before pool dispatch so raw transport callback capabilities cannot
  bypass the EgressWeave HTTP policy surface.
- Require outbound request-header names and values to be exact built-in `bytes`.
  Byte subclasses fail closed before field parsing or subclass-defined Python
  behavior can run, preserving the generic denial boundary before HTTPCore
  dispatch.
- Remove the repository-write publisher from the autonomous product scheduler
  and disable hourly scheduler auto-merge. Verified model output now ends at a
  short-lived handoff; any pull-request merge remains current-head reviewed and
  operator-controlled under normal protection.
- Canonicalize the public manifest writer's optional `forbidden_root` before any
  output-parent creation or output-path access. Missing, non-directory,
  symlinked, unresolvable, or otherwise noncanonical roots now fail with one
  stable non-leaking error, and every pre-write, descriptor-bound, and post-sync
  containment check reuses the same resolved directory authority.
- Revalidate the complete canonical evidence set and the closed owner-only
  manifest after publication but before reporting success. A second independent
  bounded evidence pass must reproduce the exact strict manifest bytes, while a
  bounded descriptor-bound reread must equal the published output. Late evidence
  additions, removals, substitutions, semantic drift, output replacement,
  disappearance, redirection, or growth now fail closed without creating a
  trusted handoff.
- Bind the release-evidence directory to its canonical absolute real path and
  reject any symbolic link in the final or ancestor path components. All payload
  verification and manifest-output exclusion now use that same resolved root, so
  retargeting a caller-supplied ancestor link cannot switch the verified directory
  or place a handoff manifest inside the set that was actually accepted.
- Recheck the manifest output parent against the verified evidence directory
  immediately before exclusive creation, after descriptor binding, and after
  durable synchronization. Redirecting a previously safe parent through a
  directory symlink during evidence verification now fails closed before a
  trusted handoff can be issued inside the sealed set.
- Reject legacy five-file release evidence whose repository and source commit
  exist only as caller assertions. The canonical source-identity payload is
  strict, bounded, descriptor-bound, checksum-covered, and rehashed through final
  manifest issuance; malformed, noncanonical, stale, mixed, or relabeled source
  identity now fails closed without claiming build provenance.
- Bind each selected release-evidence payload to an opened regular-file
  descriptor and its current path identity, bracket parsed checksum and SBOM
  bytes with bounded digests, retain the accepted `SHA256SUMS` snapshot through
  final verification, and rehash every distribution and SBOM after semantic
  checks. The handoff manifest is detached as strict JSON before filesystem
  access, created owner-only through an exclusive non-clobbering descriptor,
  durably synchronized, and path-bound again after writing. Symlink substitution,
  stale-output overwrite, Python-only JSON coercion, disappearing paths, or
  mutation of any accepted evidence file now fail before trusted manifest
  issuance.
- Serialize attestable CycloneDX evidence from one detached exact-document
  snapshot immediately before output. The writer revalidates the content-bound
  serial on that snapshot, while mutation-induced encoding failures fail closed
  before file creation so validated identity cannot diverge from emitted bytes.
- Reject PEP 508 extras in hash-locked runtime entries used for SBOM parity.
  Extras can activate transitive packages outside the reviewed dependency graph,
  so evidence generation now fails closed instead of understating executable
  runtime scope.
- Replace HTTPX private `DEFAULT_LIMITS` coupling with explicit finite pool
  policy. Contradictory or unbounded configuration fails during trusted startup,
  exact normalized limits reach both HTTPCore pools, and connection-capacity
  drift participates in deterministic audit fingerprints.
- Bound the exact percent-encoded outbound path and optional query delegated to
  HTTPCore. Targets larger than `max_request_target_bytes` fail before pool
  dispatch, denied request streams are released in synchronous and asynchronous
  clients, hostile cleanup failures remain behind a fresh generic policy error,
  targets are never truncated, and the normalized budget participates in
  deterministic decision fingerprints.
- Enforce immutable finite connect, read, write, and connection-pool timeout
  ceilings immediately before synchronous or asynchronous HTTPCore dispatch.
  Missing or disabled phase values receive policy maxima, larger values are
  capped, stricter finite values are preserved, malformed timeout metadata fails
  with the generic non-leaking policy error, and timeout policy drift is bound
  into deterministic audit fingerprints.
- Bound each DNS validation result to at most
  `EgressPolicy.max_resolved_addresses` unique candidates, defaulting to 16.
  Duplicate resolver rows collapse without consuming capacity, over-limit
  answers fail closed instead of being truncated, stricter current policies are
  reapplied to signed validation state, and audit fingerprints include the
  normalized limit before synchronous or asynchronous connection attempts.
- Replace the hourly product-development model executor with SHA-256-verified
  OpenCode 1.18.13 using the existing `NVIDIA_NIM_API_KEY` secret through
  OpenCode's `NVIDIA_API_KEY` contract. Block-mode runner egress, deny-by-default
  tools, credential-disclosure detection, isolated reverification, and normal PR
  protections remain mandatory; the central review scheduler and inherited review
  agent identity contract are unchanged.
- Paginate and aggregate every GitHub REST page at all three zero-open-PR
  boundaries so an open pull request beyond the first 100 results still blocks
  model execution, independent reverification, and publication.
- Bound outbound request-body consumption in both pinned transports. Oversized
  declared `Content-Length` values fail before connection-pool dispatch, while
  chunked, missing-length, and dishonestly under-declared bodies are counted as
  their synchronous or asynchronous streams are consumed. The first
  over-budget chunk is withheld, the caller stream is closed, and the generic
  policy error is raised, limiting CWE-400 resource exhaustion without exposing
  policy thresholds or request details.
- Bound final outbound request-header field fanout and cumulative name/value
  bytes before HTTPCore connection-pool dispatch. The exact fields are counted
  after trusted `Host` and `Accept-Encoding: identity` rewriting, repeated
  fields count independently, malformed or failing metadata iterators fail
  closed, rejected request streams are released synchronously or asynchronously,
  cleanup failures remain behind the generic non-leaking denial boundary, and
  both limits participate in deterministic policy and decision fingerprints.
- Bound decoded response-header field fanout and cumulative name/value bytes
  before constructing a caller-visible HTTPX response. Repeated fields count
  independently, malformed downstream metadata fails closed, rejected source
  streams are released synchronously or asynchronously, cleanup failures remain
  behind the generic non-leaking denial boundary, and both limits participate
  in deterministic policy and decision fingerprints.

## [0.3.0] - 2026-08-04

### Added
- Add pull-request package acceptance for wheel and source distributions,
  including SPDX license metadata, archive path validation, PEP 561 marker
  checks, installed-wheel smoke testing outside the source tree, and
  deterministic `SHA256SUMS` evidence.
- Add a credential-separated release workflow that rebuilds an immutable
  published tag with hash-locked Hatchling tooling, verifies version and
  dated changelog binding, publishes through PyPI Trusted Publishing with
  attestations, and attaches checksummed artifacts to the GitHub Release.
- Enforce 100% production statement and branch coverage on every supported
  Python 3.10–3.13 CI job with one canonical coverage.py configuration, a
  SHA-256-locked coverage artifact, and deterministic tests for defensive DNS,
  policy, synchronous transport, and asynchronous connection-race branches.
- Require useful docstrings on every shipped module, class, function, and
  method through an AST-based repository contract, keeping security-sensitive
  internals readable without source-code archaeology.
- Add `EgressPolicy.max_response_bytes` with a secure finite 16 MiB default,
  positive integer or ASCII decimal-string configuration, and fail-fast
  rejection of values that could silently remove the response resource bound.
- Add regression coverage and standards-grounded packaging documentation for
  the PEP 561 `py.typed` marker, preventing future releases from silently
  losing downstream type-checker and language-server discovery.
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
- Bind every pull-request quality and package-acceptance job to the immutable
  event head SHA, verify the checked-out commit before executing repository
  code, and name release evidence with that source SHA so a synthetic merge or
  stale revision cannot be mistaken for exact-current-head validation.
- Gate stable publication through a protected-main manual dispatch and separate
  build, tag, PyPI OIDC, and GitHub Release identities. The public GitHub Release
  is now created from a complete draft only after PyPI publication succeeds,
  exact tag identity is rechecked, and release evidence checksums pass.
- Reject any additional wheel or source-distribution archive before checksum
  generation or publication, so publisher globs cannot carry an unintended
  second package alongside the canonical EgressWeave artifacts.
- Bind every permitted destination port to its exact normalized hostname through
  `allowed_authorities` and `EgressPolicy.from_authorities(...)`. Ambiguous
  many-host by many-port `from_hosts(...)` configuration now fails at policy
  construction, and unlisted cross-pairs fail before DNS resolution instead of
  inheriting a port intended for another service on the allowlist.
- Bound response-body consumption in both pinned transports. Requests now force
  one trusted `Accept-Encoding: identity` field, and body-bearing responses that
  nevertheless apply a content coding are closed and rejected before HTTPX can
  allocate decompressed output. Unsafe duplicate, malformed, or over-budget
  `Content-Length` values fail before a caller-visible response is returned,
  while chunked, close-delimited, missing-length, and dishonestly under-declared
  identity bodies are counted during streaming. The first over-budget chunk is
  withheld, the source stream is closed, and the generic policy error is raised,
  limiting CWE-400 resource exhaustion without misinterpreting RFC 9112 bodyless
  response metadata.
- Stagger asynchronous pinned TCP connection attempts using RFC 8305's 250 ms
  default instead of launching every validated address simultaneously. Later
  attempts receive only the remaining connection-timeout budget, the first
  success cancels and awaits all losers, and immediate failures can advance the
  next candidate without an idle delay. This preserves DNS pinning while
  reducing avoidable task and network bursts (CWE-400).
- Require every request method reaching a pinned transport to be the exact
  canonical uppercase RFC 9110 `token` authorized by policy. Leading or trailing
  whitespace, embedded separators or controls, non-ASCII spellings, and
  alternate casing now fail with the generic policy error before HTTPCore
  dispatch, preventing malformed request-line parser differentials while
  preserving normalized operator configuration.
- Reject caller-supplied connection controls, protocol-upgrade fields, and
  proxy-only authentication fields before synchronous or asynchronous HTTPCore
  dispatch. `Connection`, `Keep-Alive`, `Upgrade`, `Proxy-Authenticate`,
  `Proxy-Authorization`, and `Proxy-Connection` now fail with the generic policy
  error, preventing an approved HTTP request from switching protocols or leaking
  proxy credentials while preserving ordinary origin `Authorization`.
- Reject ambiguous HTTP/1.1 request-body framing before synchronous or
  asynchronous connection-pool dispatch. Duplicate `Content-Length` or
  `Transfer-Encoding` fields, mixed framing fields, malformed decimal lengths,
  comma-joined lengths, and transfer codings other than a single `chunked`
  coding now fail with the generic policy error, preventing CWE-444 parser
  differentials while preserving ordinary fixed-size and HTTPX streaming bodies.
- Validate every outbound raw HTTP field name and value before HTTPCore
  dispatch, reject malformed names, control octets, and leading or trailing
  whitespace with the generic policy error, then restore exactly one trusted
  `Host` field. This prevents parser differentials from turning ambiguous raw
  headers into request-routing or request-smuggling channels.
- Reject caller-supplied HTTPX/HTTPCore `target` request extensions before the
  synchronous or asynchronous connection pool. Absolute-form proxy targets can
  carry a second, unvalidated destination independently of the pinned URL, so
  every request target is now derived exclusively from the validated URL path.
- Require every local-development target, including `localhost` and
  `localhost.localdomain`, to appear explicitly in `allowed_hosts` before DNS
  resolution. `allow_local=True` now widens only the permitted address class;
  it no longer grants an implicit hostname. Loopback IP-literal URLs remain
  forbidden, preventing a policy intended for one container alias from reaching
  an unrelated local listener on the same authorized port.
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
