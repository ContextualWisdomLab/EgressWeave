# Research grounding

`egressweave` implements well-established outbound-request-safety guidance
rather than an ad-hoc heuristic. The primary sources:

## SSRF — CWE-918 / OWASP

- **CWE-918: Server-Side Request Forgery (SSRF).** A server can be induced to
  make requests to unintended destinations — internal services, the cloud
  metadata endpoint at `169.254.169.254`, loopback admin panels, or unexpected
  services on alternate ports. egressweave's exact hostname and destination-
  port policy plus address classifier reject every unapproved authority and
  non-globally-routable target (private, loopback, link-local, reserved,
  multicast, unspecified, non-global).
- **OWASP SSRF Prevention Cheat Sheet.** Recommends an *allowlist* of permitted
  hosts (never a denylist), rejecting non-standard schemes and embedded
  credentials, disabling redirects, and validating the *resolved* IP — all
  implemented here.

## DNS rebinding / TOCTOU — CWE-350

- **CWE-350: Reliance on Reverse DNS Resolution / time-of-check to
  time-of-use.** If a URL is validated by resolving and checking a hostname and
  then fetched by hostname again, a short-TTL attacker DNS record can return a
  public IP at check time and a private IP at connect time. egressweave resolves
  once, validates *every* returned address, and **pins** those addresses into
  the transport, re-validating immediately before each connect and refusing any
  host/port drift. The `Host` header is rewritten to the validated netloc.

## Internationalized hostnames — IDNA2008 / UTS #46

- **RFC 5890 / RFC 5891:** define the IDNA2008 framework and lookup protocol
  that represents internationalized labels as DNS-compatible ASCII A-labels.
- **Unicode Technical Standard #46:** defines deterministic compatibility
  mapping and validation before IDNA2008 lookup. egressweave uses
  non-transitional UTS #46 processing with STD3 ASCII rules so policy entries,
  request hosts, DNS lookups, TLS SNI, and transport pinning share one canonical
  ASCII representation. Labels that fail processing are rejected.

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
