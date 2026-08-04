# Outbound request-body resource limits

## Decision

Every EgressWeave policy defines a finite `max_request_bytes` budget. Both
pinned transports apply the same two-stage fail-closed control:

1. after request-header syntax and framing validation, a single declared
   `Content-Length` greater than the policy budget is rejected before
   connection-pool dispatch; and
2. the actual synchronous or asynchronous request stream is counted chunk by
   chunk, so chunked, missing-length, and dishonestly under-declared bodies
   cannot exceed the same budget.

The first chunk that would exceed the budget is withheld, the caller-provided
stream is closed, and `EgressNotAllowedError` retains its generic public message.
This preserves non-leaking runtime behavior while preventing an accidental or
adversarial producer from turning an approved authority into an unbounded
outbound resource sink.

The byte counter belongs to the bounded wrapper rather than an individual
iterator. Repeated iteration, partial re-consumption, or transport retry of a
replayable source therefore shares one cumulative budget instead of granting a
fresh allowance each time the stream is consumed.

## Why declared length is not sufficient

HTTP content is a stream of octets after message framing is removed. A sender
can use a known `Content-Length`, but streaming content can instead use chunked
framing, and an untrusted producer can provide metadata that understates the
bytes it actually emits. Declared-length validation is therefore an early
rejection optimization, not the enforcement boundary. Actual stream accounting
is required independently of framing metadata.

The comparison for declared length is performed on normalized decimal text
rather than converting arbitrarily long attacker-influenced values to an
integer. Earlier request-safety checks already reject duplicate, mixed,
non-decimal, or unsupported framing, while this layer remains independently
fail closed if invoked with malformed metadata.

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
  HTTPCore; the chunk that crosses the limit is never forwarded.
- **No retry reset:** all iterations of one bounded stream share the same byte
  counter, preventing replayable sources from multiplying the configured limit.
- **Resource release:** synchronous and asynchronous source streams are closed
  on declared-length denial and actual-byte overrun.
- **Generic failure:** runtime errors do not disclose the configured limit,
  declared size, consumed size, destination, or rejection rule.
- **Deterministic parity:** synchronous and asynchronous paths implement the same
  preflight and streaming semantics and are covered by offline regression tests.

## Authoritative references

Internet Engineering Task Force. (2022). *HTTP semantics* (RFC 9110),
sections 6.4 and 8.6. RFC Editor. https://www.rfc-editor.org/rfc/rfc9110.html

MITRE. (2026). *CWE-400: Uncontrolled resource consumption*. Common Weakness
Enumeration. https://cwe.mitre.org/data/definitions/400.html

Open Worldwide Application Security Project. (n.d.). *Denial of service cheat
sheet*. OWASP Cheat Sheet Series.
https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html
