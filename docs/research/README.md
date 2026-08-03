# Research grounding

`egressweave` implements well-established outbound-request-safety guidance
rather than an ad-hoc heuristic. The primary sources:

## SSRF — CWE-918 / OWASP

- **CWE-918: Server-Side Request Forgery (SSRF).** A server can be induced to
  make requests to unintended destinations — internal services, the cloud
  metadata endpoint at `169.254.169.254`, loopback admin panels. egressweave's
  address classifier rejects every non-globally-routable target (private,
  loopback, link-local, reserved, multicast, unspecified, non-global).
- **OWASP SSRF Prevention Cheat Sheet.** Recommends an *allowlist* of permitted
  hosts (never a denylist), rejecting non-standard schemes and embedded
  credentials, disabling redirects, and validating the *resolved* IP — all
  implemented here.
- **OWASP Top 10 A10:2021 SSRF.** Recommends positive allowlists for URL scheme,
  port, and destination, plus deny-by-default network controls. EgressWeave
  applies the same least-authority principle to the request method at the final
  transport boundary rather than trusting a helper call earlier in the flow.

## HTTP method authority — RFC 9110

- **RFC 9110, section 9.3.6 (`CONNECT`).** `CONNECT` asks a proxy to establish a
  tunnel to the host and port carried in the method-specific request target and
  then blindly forward traffic. That tunnel destination is a second authority
  channel independent of the URL authority EgressWeave validated and pinned.
- EgressWeave therefore uses a positive HTTP-method allowlist for every pinned
  client, defaults to ordinary API methods, and refuses `CONNECT` even when an
  operator attempts to add it. Less common non-tunnelling methods such as
  WebDAV verbs require explicit opt-in.

Primary references:

- [RFC 9110: HTTP Semantics](https://www.rfc-editor.org/rfc/rfc9110.html#name-connect)
- [OWASP SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
- [OWASP Top 10 A10:2021 SSRF](https://owasp.org/Top10/2021/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/)

## Secure defaults and fail-secure behavior — OWASP

- **OWASP Secure Product Design Cheat Sheet.** Establish secure defaults,
  minimize attack surface, and fail securely to those defaults.
- **OWASP Fail Securely.** A security-control exception or indeterminate state
  should follow the same execution path as denial, not enable behavior that the
  control would normally reject.

Accordingly, an empty or absent base URL is treated as an indeterminate target,
not permission to use a generic transport. The public client builders preserve
their `(None, client)` return shape but that client denies every request before
network I/O.

## DNS rebinding / TOCTOU — CWE-350

- **CWE-350: Reliance on Reverse DNS Resolution / time-of-check to
  time-of-use.** If a URL is validated by resolving and checking a hostname and
  then fetched by hostname again, a short-TTL attacker DNS record can return a
  public IP at check time and a private IP at connect time. egressweave resolves
  once, validates *every* returned address, and **pins** those addresses into
  the transport, re-validating immediately before each connect and refusing any
  host/port drift. The `Host` header is rewritten to the validated netloc.

## Concurrent connection — RFC 8305 (Happy Eyeballs)

When a validated hostname yields several addresses, the pinned transport races
connections across them and takes the first to succeed (cancelling the rest),
following the spirit of RFC 8305's concurrent-connection approach — while never
connecting to an address that did not pass validation.

## Provenance

Extracted behaviour-preserving from the naruon control plane's LLM-provider
egress guard (`backend/services/llm_provider_urls.py`). The sole change was
injecting `EgressPolicy` in place of an application settings object, so security
fixes can be ported in both directions.
