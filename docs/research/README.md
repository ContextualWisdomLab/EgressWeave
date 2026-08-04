# Research grounding

`egressweave` implements well-established outbound-request-safety guidance
rather than an ad-hoc heuristic. The primary sources follow.

## SSRF — CWE-918 / OWASP

- **CWE-918: Server-Side Request Forgery (SSRF).** A server can be induced to
  make requests to unintended destinations—internal services, cloud metadata,
  loopback admin panels, or unexpected listeners on an otherwise trusted host.
- **OWASP SSRF Prevention Cheat Sheet.** Recommends an allowlist of permitted
  destinations, rejecting non-standard schemes and embedded credentials,
  disabling redirects, and validating resolved IP addresses.
- **OWASP Top 10 A10:2021 SSRF.** Explicitly recommends positive allowlists for
  URL scheme, port, and destination, with deny-by-default network controls.

EgressWeave applies those controls as one origin-oriented policy: exact
`(hostname, port)` authority pairs, allowed HTTP methods, checked resolved
addresses, and a pinned transport that cannot silently re-resolve elsewhere.

## Origin authority and ports — RFC 9110

RFC 9110 section 4.3.1 defines an HTTP origin as the triple of **scheme, host,
and port**. Two URLs with the same hostname but different ports are distinct
origins and can identify different services. A hostname-only allowlist therefore
leaves a meaningful authority dimension uncontrolled.

EgressWeave authorizes complete normalized authority pairs rather than separate
host and port sets. `from_hosts(...)` derives exact pairs only when several hosts
share one port or one host intentionally exposes several ports. Several hosts
plus several ports is ambiguous and fails at construction; callers enumerate
those destinations with `from_authorities(...)`. The complete pair is checked
before DNS resolution, so a port intended for one allowlisted host cannot be
combined with another host to reach an unintended listener. Explicit port zero
is rejected rather than being silently replaced by the scheme default. See
[Exact host-and-port authority pairs](exact-authority-pairs.md).

## HTTP method authority — RFC 9110

- **RFC 9110, section 9.1.** A method is one case-sensitive HTTP `token`; the
  standardized methods use uppercase US-ASCII spellings. EgressWeave therefore
  distinguishes normalized operator configuration from request-boundary input:
  the actual method reaching a pinned transport must already be the exact
  canonical token authorized by policy. Whitespace-wrapped, malformed,
  non-ASCII, or alternate-case spellings fail before HTTPCore dispatch rather
  than being repaired and forwarded under a different interpretation.
- **RFC 9110, section 9.3.6 (`CONNECT`).** `CONNECT` asks a proxy to establish a
  tunnel to the host and port carried in the method-specific request target and
  then blindly forward traffic. That tunnel destination is a second authority
  channel independent of the URL authority EgressWeave validated and pinned.
- EgressWeave therefore uses a positive HTTP-method allowlist for every pinned
  client, defaults to ordinary API methods, and refuses `CONNECT` even when an
  operator attempts to add it. Less common non-tunnelling methods such as
  WebDAV verbs require explicit opt-in.

See [Canonical request-method enforcement](canonical-request-methods.md) for the
request-line threat model and fail-closed transport decision.

Primary references:

- [RFC 9110: HTTP Semantics—URI Origin](https://www.rfc-editor.org/rfc/rfc9110.html#section-4.3.1)
- [RFC 9110: HTTP Semantics—Methods Overview](https://www.rfc-editor.org/rfc/rfc9110.html#section-9.1)
- [RFC 9110: HTTP Semantics—CONNECT](https://www.rfc-editor.org/rfc/rfc9110.html#name-connect)
- [OWASP SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
- [OWASP Top 10 A10:2021 SSRF](https://owasp.org/Top10/2021/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/)
- [CWE-918: Server-Side Request Forgery](https://cwe.mitre.org/data/definitions/918.html)
- [CWE-444: Inconsistent Interpretation of HTTP Requests](https://cwe.mitre.org/data/definitions/444.html)

## Protocol switching and proxy-only fields — RFC 9110

A validated HTTP origin can still be abused as a long-lived channel if an
untrusted request initiates a protocol upgrade. RFC 9110 also scopes proxy
authentication fields to a proxy hop, while EgressWeave deliberately disables
proxy discovery and connects directly to the pinned origin.

EgressWeave therefore rejects caller-supplied `Connection`, `Keep-Alive`,
`Upgrade`, `Proxy-Authenticate`, `Proxy-Authorization`, and `Proxy-Connection`
fields immediately before dispatch. This prevents per-request protocol
switching, connection-control ambiguity, and proxy-credential leakage while
preserving ordinary origin `Authorization` and HTTPX's validated request-body
framing. See [Protocol switching and proxy-only request fields](protocol-switching-request-fields.md).

## Secure defaults and fail-secure behavior — OWASP

- **OWASP Secure Product Design Cheat Sheet.** Establish secure defaults,
  minimize attack surface, and fail securely to those defaults.
- **OWASP Fail Securely.** A security-control exception or indeterminate state
  should follow the same execution path as denial, not enable behavior that the
  control would normally reject.

Accordingly, the default port surface is 443 rather than every possible TCP
port, and an empty or absent base URL is treated as an indeterminate target—not
permission to use a generic transport. The public client builders preserve
their `(None, client)` return shape, but that client denies every request before
network I/O.

## Security-control configuration — CWE-20 / OWASP ASVS

- **CWE-20: Improper Input Validation.** Security-relevant input should be
  checked for its required type as well as its acceptable value range and
  business meaning; values that do not strictly conform should be rejected.
- **OWASP ASVS access-control design.** Security controls should fail securely
  when configuration or execution is indeterminate.

`allow_local` materially widens the address classes that a policy may reach.
Python treats non-empty strings such as `"false"` as truthy, so permissive
coercion would turn a common configuration-parsing mistake into local-network
authority. EgressWeave therefore accepts only the actual boolean values `True`
and `False`; strings, integers, and other ambiguous values fail during policy
construction before any URL is resolved.

Primary references:

- [CWE-20: Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)
- [OWASP Application Security Verification Standard](https://owasp.org/www-project-application-security-verification-standard/)

## Internationalized hostname identity — RFC 5891 / UTS #46

RFC 5891 requires domain names placed into non-IDNA-aware protocol slots and
DNS lookups to use ASCII labels, and requires comparisons to use equivalent
forms. Unicode Technical Standard #46 defines stable non-transitional mapping
and validation for converting user-facing Unicode names to IDNA2008-compatible
ASCII A-labels. Its `ToASCII` operation also validates label and total DNS length
constraints; STD3 rules restrict ASCII label characters to letters, digits, and
hyphens.

EgressWeave canonicalizes both trusted allowlist entries and candidate URL
hostnames to one lowercase ASCII A-label identity before allowlist comparison,
DNS resolution, TLS SNI construction, and HTTP authority construction. This
prevents a Unicode hostname from passing policy validation but failing later at
an ASCII-only transport boundary, and rejects malformed labels at startup
instead of deferring them to the resolver. A single trailing DNS root dot is
accepted and removed from the comparison form. Unicode confusables remain a
configuration-review concern—the control guarantees exact canonical identity,
not visual similarity detection.

Primary references:

- [RFC 5891: Internationalized Domain Names in Applications (IDNA)](https://www.rfc-editor.org/rfc/rfc5891)
- [Unicode Technical Standard #46: Unicode IDNA Compatibility Processing](https://unicode.org/reports/tr46/)

## DNS rebinding / TOCTOU — CWE-350

- **CWE-350: Reliance on Reverse DNS Resolution / time-of-check to
  time-of-use.** If a URL is validated by resolving and checking a hostname and
  then fetched by hostname again, a short-TTL attacker DNS record can return a
  public IP at check time and a private IP at connect time. EgressWeave resolves
  once, validates every returned address, and pins those addresses into the
  transport, re-validating immediately before each connect and refusing any
  host/port drift. The `Host` header is rewritten to the validated netloc.

## Staggered concurrent connection — RFC 8305 (Happy Eyeballs)

When a validated hostname yields several addresses, RFC 8305 section 5 advises
clients not to start every connection simultaneously because doing so creates
unreasonable network load. It recommends starting one candidate first, adding
later attempts one at a time, cancelling losers after the first success, and
using a 250 ms default Connection Attempt Delay.

The asynchronous pinned transport follows that schedule while preserving one
caller-supplied connection-timeout budget. Every candidate remains one of the
addresses validated and pinned before transport construction, each address is
rechecked immediately before connect, and every losing task is cancelled and
awaited. The synchronous transport remains sequential and therefore does not
create a simultaneous-attempt burst.

See [Staggered pinned connection attempts](staggered-connection-attempts.md) for
the scheduler, timeout, and resource-consumption rationale.

Primary references:

- [RFC 8305 section 5: Connection Attempts](https://www.rfc-editor.org/rfc/rfc8305.html#section-5)
- [RFC 8305 section 8: Summary of Configurable Values](https://www.rfc-editor.org/rfc/rfc8305.html#section-8)
- [CWE-400: Uncontrolled Resource Consumption](https://cwe.mitre.org/data/definitions/400.html)

## Provenance

Extracted behaviour-preserving from the naruon control plane's LLM-provider
egress guard (`backend/services/llm_provider_urls.py`). The original extraction
replaced the application settings object with an injected `EgressPolicy`, so
security fixes can be ported in both directions.
