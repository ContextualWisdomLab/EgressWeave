# Outbound request-body resource limits

## Decision

Every EgressWeave policy defines a finite `max_request_bytes` budget. Both
pinned transports apply the same fail-closed controls:

1. after request-header syntax and framing validation, a single declared
   `Content-Length` greater than the policy budget is rejected before
   connection-pool dispatch;
2. every synchronous or asynchronous request stream is counted chunk by chunk,
   so chunked, missing-length, and dishonestly under-declared bodies cannot
   exceed the policy budget; and
3. when `Content-Length` is present, actual stream consumption must equal that
   declaration exactly. Bytes beyond the declared boundary are withheld, while
   a stream that ends early fails instead of completing mismatched framing.

The first chunk that would exceed either the policy budget or the declared
message boundary is withheld, the caller-provided stream is closed, and
`EgressNotAllowedError` retains its generic public message. This preserves
non-leaking runtime behavior while preventing an accidental or adversarial
producer from turning an approved authority into an unbounded outbound resource
sink or a request-framing differential.

The byte counter belongs to the bounded wrapper rather than an individual
iterator. Repeated iteration, partial re-consumption, or transport retry of a
replayable source therefore shares one cumulative budget instead of granting a
fresh allowance each time the stream is consumed.

## Why declared length is both an early gate and an exact boundary

HTTP content is a stream of octets after message framing is removed. A sender
can use a known `Content-Length`, while streaming content can instead use
chunked framing. An untrusted producer can provide metadata that understates or
overstates the bytes it actually emits. Declared-length validation is therefore
not the sole resource-enforcement boundary: actual stream accounting is always
required independently of framing metadata.

At the same time, RFC 9112 makes `Content-Length` part of HTTP/1.1 message
framing: it determines where a content-bearing message body ends. Forwarding
more bytes than declared can let downstream agents disagree about where the
next request begins, while emitting fewer bytes leaves an incomplete message.
EgressWeave therefore treats a valid declared length as an exact byte contract,
not merely a maximum. This complements the existing rejection of duplicate,
mixed, malformed, and unsupported framing fields and narrows the interpretation
differences associated with HTTP request smuggling (CWE-444).

The preflight comparison uses normalized decimal text instead of passing an
arbitrarily long attacker-influenced value to Python's integer parser. A value
that is already proven no larger than the configured policy budget is converted
with a bounded decimal accumulation step and passed to the streaming wrapper as
the exact expected length.

## Budget and compatibility

The secure default is 16 MiB, matching the existing response-body default.
Operators can select a smaller or larger positive finite value for a specific
integration through either `EgressPolicy.from_hosts(...)` or
`EgressPolicy.from_authorities(...)`. Positive ASCII decimal strings are
accepted for environment-variable ergonomics. Zero, negative, boolean,
fractional, signed, non-ASCII, empty, or otherwise malformed values fail during
policy construction rather than silently removing the bound.

The limit measures bytes consumed from the caller's HTTPX byte stream. It does
not parse or reinterpret JSON, multipart, protobuf, or other application
formats, so the control remains provider-neutral and reusable as a standalone
library or an imported service module.

## Security properties

- **No authority-policy bypass:** request-size enforcement occurs only after the
  existing method, URL authority, TLS identity, raw-field, proxy-isolation, and
  framing checks and immediately before HTTPCore dispatch.
- **No partial over-budget chunk:** a chunk is counted before it is yielded to
  HTTPCore; the chunk that crosses the policy or declared boundary is never
  forwarded.
- **Exact declared framing:** a stream with `Content-Length` succeeds only when
  its actual total equals that decimal octet count. Both excess and truncation
  fail closed before a successful response can become caller-visible.
- **No retry reset:** all iterations of one bounded stream share the same byte
  counter, preventing replayable sources from multiplying the configured limit.
- **Resource release:** synchronous and asynchronous source streams are closed
  on declared-length denial, policy overrun, or framing mismatch; cleanup
  exceptions from caller-controlled streams do not replace the generic denial.
- **Generic failure:** runtime errors do not disclose the configured limit,
  declared size, consumed size, destination, or rejection rule.
- **Deterministic parity:** synchronous and asynchronous paths implement the same
  preflight, exact-framing, and streaming semantics and are covered by offline
  regression tests.

## Authoritative references

Fielding, R., Nottingham, M., & Reschke, J. (2022). *HTTP/1.1* (RFC 9112),
sections 6.2 and 6.3. RFC Editor. https://www.rfc-editor.org/rfc/rfc9112.html

Fielding, R., Nottingham, M., & Reschke, J. (2022). *HTTP semantics* (RFC
9110), sections 6.4 and 8.6. RFC Editor.
https://www.rfc-editor.org/rfc/rfc9110.html

MITRE. (2026). *CWE-400: Uncontrolled resource consumption*. Common Weakness
Enumeration. https://cwe.mitre.org/data/definitions/400.html

MITRE. (2026). *CWE-444: Inconsistent interpretation of HTTP requests
(HTTP request/response smuggling)*. Common Weakness Enumeration.
https://cwe.mitre.org/data/definitions/444.html

Open Worldwide Application Security Project. (n.d.). *Denial of service cheat
sheet*. OWASP Cheat Sheet Series.
https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html
