# Bounded response-body consumption

## Decision

Every pinned client applies a finite identity-coded response-body budget from
`EgressPolicy.max_response_bytes`. The secure default is 16 MiB. A specific
integration may set another positive byte count, including a decimal string from
an environment variable, but zero, negative, boolean, fractional, non-ASCII, or
otherwise malformed values fail at policy construction.

The control is enforced at three boundaries:

1. Every outbound request replaces caller compression preferences with one
   trusted `Accept-Encoding: identity` field.
2. A body-bearing response that applies `Content-Encoding`, or has an unsafe
   `Content-Length`, is rejected before a caller-visible `httpx.Response` is
   returned. Exactly one canonical `Content-Encoding: identity` is accepted when
   present. Duplicate, comma-joined, signed, malformed, or over-budget length
   metadata fails through the generic `EgressNotAllowedError` boundary and the
   source stream is closed.
3. Every transfer-decoded identity body chunk must be an exact built-in `bytes`
   value before its length is counted or the chunk becomes caller-visible. A
   subclass, alternate buffer object, or other malformed backend value is not
   coerced: it is rejected, the source stream is closed, and the stable generic
   policy error is raised. Valid chunks are then counted while consumed. This
   authoritative check covers chunked, close-delimited, missing-length, and
   dishonestly under-declared responses. The first valid byte chunk that would
   exceed the policy budget is not exposed; the source stream is closed and the
   same generic policy error is raised. Policy-denial cleanup is best effort:
   exceptions or self-cancellation produced by a dependency-injected child
   `close()` or `aclose()` path are discarded before the stable denial exception
   is created, so backend-private cleanup details are not retained as its cause
   or exception context. Cancellation directed at the consuming coordinator
   while async cleanup is awaited still propagates.

Responses to `HEAD`, informational responses, `204 No Content`, and
`304 Not Modified` are treated as bodyless. Their `Content-Encoding` and
`Content-Length` fields can describe selected-representation metadata rather than
bytes carried in that message and therefore are not interpreted as transferred
body data.

## Threat model

Destination allowlisting and DNS pinning establish *where* a request may go.
They do not establish that the allowlisted peer will remain trustworthy or
return a bounded amount of data. A compromised vendor API, attacker-controlled
allowed tenant endpoint, compression expansion, or simple upstream defect can
keep delivering or producing bytes until process memory, disk-backed buffering,
connection capacity, or worker time is exhausted. This is an availability
failure in the CWE-400 uncontrolled-resource-consumption family.

The HTTPX Developer Interface exposes raw response streaming through byte
iterators such as `Response.iter_raw()` and `Response.aiter_raw()`. EgressWeave
also supports provider-neutral, dependency-injected transport components, so
runtime objects at that boundary are validated rather than trusted solely because
the Python interface is typed. In Python, a `bytes` subclass can supply custom
special methods such as `__len__`; counting such an object before validating its
exact runtime type could make an attacker-controlled length disagree with the
byte buffer later exposed to a caller. EgressWeave accepts only exact built-in
`bytes` chunks and never calls conversion or length protocols on a malformed
chunk. Cleanup performed because the policy has already denied a stream is also
an untrusted backend boundary: cleanup is attempted, backend cleanup exceptions
or child self-cancellation are consumed internally, and the caller receives a
newly created generic policy denial with no retained backend cause or exception
context. Python 3.13 documents that `CancelledError` is a `BaseException` and
that `asyncio.gather(..., return_exceptions=True)` treats a cancelled child as a
result while cancellation of the gather itself propagates to submitted
awaitables. EgressWeave uses that distinction only for post-denial child cleanup;
cancellation of the consuming coordinator remains visible. These rules are
EgressWeave integration-hardening contracts, not claims that HTTPX ordinarily
emits malformed chunks or hostile cleanup failures.

A header-only length check is insufficient because HTTP permits responses whose
body length is determined by transfer coding or connection closure, and a
hostile peer can lie about `Content-Length`. A post-decompression counter alone
is also insufficient: a single compressed chunk can allocate a large decoded
buffer before the counter observes it. EgressWeave therefore requests identity
coding, rejects content-coded body-bearing responses before HTTPX decoding, and
combines early metadata validation with exact-byte streaming accounting.

## Compatibility

This is an intentional pre-1.0 secure-default tightening. Existing ordinary JSON
API integrations generally continue to work because HTTP origins are expected to
honor `Accept-Encoding: identity`. Integrations that require compressed response
content must perform that transfer through a separately reviewed client with a
bounded streaming decoder; EgressWeave does not silently accept compression.
Integrations that legitimately download larger identity-coded artifacts must set
a bounded, integration-specific `max_response_bytes` value. There is no unlimited
sentinel because a deployment mistake must not silently remove the boundary.
Custom injected response streams must satisfy the same byte-stream contract as
HTTPX and yield exact built-in `bytes` chunks; accepting subclass or buffer
coercion would weaken the resource-accounting trust boundary. Ordinary
caller-requested `close()` or `aclose()` behavior remains unchanged; only cleanup
performed after a policy denial discards backend cleanup exceptions or child
self-cancellation, and cancellation directed at the caller/coordinator still
propagates.

## References

Fielding, R., Nottingham, M., & Reschke, J. (2022). *HTTP semantics* (RFC 9110).
RFC Editor. https://doi.org/10.17487/RFC9110

Thomson, M., & Nottingham, M. (2022). *HTTP/1.1* (RFC 9112). RFC Editor.
https://doi.org/10.17487/RFC9112

MITRE. (2026). *CWE-400: Uncontrolled resource consumption* (CWE Version 4.20).
Common Weakness Enumeration. https://cwe.mitre.org/data/definitions/400.html

Encode OSS Ltd. (n.d.). *Developer interface*. HTTPX. Retrieved August 7, 2026,
from https://www.python-httpx.org/api/

Python Software Foundation. (2026). *Coroutines and tasks — Python 3.13.14
documentation*. Retrieved August 7, 2026, from
https://docs.python.org/3.13/library/asyncio-task.html
