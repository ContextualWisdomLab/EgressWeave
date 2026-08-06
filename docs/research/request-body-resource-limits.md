# Outbound request-body resource limits

## Decision

Every EgressWeave policy defines a finite `max_request_bytes` budget. Both
pinned transports apply the same fail-closed controls:

1. after request-header syntax and framing validation, a single declared
   `Content-Length` greater than the policy budget is rejected before
   connection-pool dispatch;
2. every synchronous or asynchronous request stream is validated as exact
   built-in `bytes` before length accounting and then counted chunk by chunk,
   so chunked, missing-length, dishonestly under-declared, and malformed runtime
   bodies cannot bypass the policy budget through an overridable length protocol;
   and
3. when `Content-Length` is present, actual stream consumption must also equal that
   declaration exactly. Bytes beyond the declared boundary are withheld, while
   a stream that ends early fails instead of completing mismatched framing.

The first chunk that is not an exact built-in `bytes` value or would exceed
either the policy budget or the declared message boundary is withheld, the
caller-provided stream is closed, and `EgressNotAllowedError` retains its
generic public message. This preserves non-leaking runtime behavior while
preventing an accidental or adversarial producer from turning an approved
authority into an unbounded outbound resource sink or a request-framing
differential.

The byte counter belongs to the bounded wrapper rather than an individual
iterator. Repeated iteration, partial re-consumption, or transport retry of a
replayable source therefore shares one cumulative budget instead of granting a
fresh allowance each time the stream is consumed.

## Exact-byte trust boundary

RFC 9110 defines HTTP content as a stream of octets. HTTPX's low-level transport
API similarly treats request streams as byte streams, but EgressWeave cannot use
a static type contract as runtime authorization evidence because applications
can construct custom stream implementations and direct `Request` objects.

A Python `bytes` subclass is still accepted by `isinstance(value, bytes)`, while
its special methods can be overridden. Counting such an object with `len()` and
then forwarding the original object would therefore let the object influence the
number of bytes EgressWeave believes it authorized. The bounded request wrappers
instead require `type(chunk) is bytes` before calling `len()` or exposing the
chunk to HTTPCore. No conversion is attempted: `bytes` subclasses, `bytearray`,
`memoryview`, buffer providers, and arbitrary iterables are rejected rather than
normalized after the network trust boundary.

This rule is provider-neutral. It does not assert that HTTPX or HTTPCore's normal
producers emit malformed chunks; it protects the dependency-injected runtime
boundary from a buggy, adversarial, or alternate producer. Synchronous and
asynchronous paths apply the same check, close the rejected source first, and
mask hostile cleanup failures behind the stable generic policy error.

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

The limit measures exact built-in bytes consumed from the caller's HTTPX byte
stream. It does not parse or reinterpret JSON, multipart, protobuf, or other
application formats, so the control remains provider-neutral and reusable as a
standalone library or an imported service module.

## Operational boundary

`max_request_bytes` is a per-request transport invariant, not a process-wide or
tenant-wide admission controller. It prevents one request stream from exceeding
its configured budget, but several concurrent requests can each consume their
own budget. Applications embedding EgressWeave must therefore pair the transport
bound with integration-appropriate concurrency limits, queue capacity,
timeouts, tenant quotas, and cancellation. Those controls belong to the host
service because only it knows workload priority and aggregate memory or network
budgets.

This separation keeps the library independently useful while avoiding a false
assurance that a per-stream byte limit alone solves aggregate denial of service.
Naruon and other CWL services can apply their own workload-level controls around
the same provider-neutral pinned client.

## Security properties

- **No authority-policy bypass:** request-size enforcement occurs only after the
  existing method, URL authority, TLS identity, raw-field, proxy-isolation, and
  framing checks and immediately before HTTPCore dispatch.
- **Exact runtime byte type:** only exact built-in `bytes` chunks are eligible
  for accounting or delivery; subclass and arbitrary-object protocols cannot
  influence the authorized byte count.
- **No partial over-budget chunk:** a chunk is counted before it is yielded to
  HTTPCore; the chunk that crosses the policy or declared boundary is never
  forwarded.
- **Exact declared framing:** a stream with `Content-Length` succeeds only when
  its actual total equals that decimal octet count. Both excess and truncation
  fail closed before a successful response can become caller-visible.
- **No retry reset:** all iterations of one bounded stream share the same byte
  counter, preventing replayable sources from multiplying the configured limit.
- **Resource release:** synchronous and asynchronous source streams are closed
  on malformed-chunk denial, declared-length denial, policy overrun, or framing
  mismatch; cleanup exceptions from caller-controlled streams do not replace the
  generic denial.
- **Generic failure:** runtime errors do not disclose the configured limit,
  declared size, consumed size, destination, or rejection rule.
- **Deterministic parity:** synchronous and asynchronous paths implement the same
  preflight, exact-byte, exact-framing, and streaming semantics and are covered
  by offline regression tests.

## Authoritative references

Fielding, R., Nottingham, M., & Reschke, J. (2022). *HTTP/1.1* (RFC 9112).
Internet Engineering Task Force. https://doi.org/10.17487/RFC9112

Fielding, R., Nottingham, M., & Reschke, J. (2022). *HTTP semantics* (RFC 9110).
Internet Engineering Task Force. https://doi.org/10.17487/RFC9110

MITRE Corporation. (2026). *CWE-400: Uncontrolled resource consumption* (CWE
Version 4.20). https://cwe.mitre.org/data/definitions/400.html

MITRE Corporation. (2026). *CWE-444: Inconsistent interpretation of HTTP
requests (HTTP request/response smuggling)* (CWE Version 4.20).
https://cwe.mitre.org/data/definitions/444.html

Encode OSS Ltd. (n.d.). *Developer interface — HTTPX*. Retrieved August 7, 2026,
from https://www.python-httpx.org/api/

Encode OSS Ltd. (n.d.). *Transports — HTTPX*. Retrieved August 7, 2026, from
https://www.python-httpx.org/advanced/transports/

Open Worldwide Application Security Project. (n.d.). *Denial of service cheat
sheet*. OWASP Cheat Sheet Series.
https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html
