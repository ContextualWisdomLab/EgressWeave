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
3. Every transfer-decoded identity body chunk is counted while it is consumed.
   This authoritative check covers chunked, close-delimited, missing-length, and
   dishonestly under-declared responses. The first chunk that would exceed the
   policy budget is not exposed; the source stream is closed and the same generic
   policy error is raised.

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

A header-only length check is insufficient because HTTP permits responses whose
body length is determined by transfer coding or connection closure, and a
hostile peer can lie about `Content-Length`. A post-decompression counter alone
is also insufficient: a single compressed chunk can allocate a large decoded
buffer before the counter observes it. EgressWeave therefore requests identity
coding, rejects content-coded body-bearing responses before HTTPX decoding, and
combines early metadata validation with streaming byte accounting.

## Compatibility

This is an intentional pre-1.0 secure-default tightening. Existing ordinary JSON
API integrations generally continue to work because HTTP origins are expected to
honor `Accept-Encoding: identity`. Integrations that require compressed response
content must perform that transfer through a separately reviewed client with a
bounded streaming decoder; EgressWeave does not silently accept compression.
Integrations that legitimately download larger identity-coded artifacts must set
a bounded, integration-specific `max_response_bytes` value. There is no unlimited
sentinel because a deployment mistake must not silently remove the boundary.

## References

Fielding, R., Nottingham, M., & Reschke, J. (2022). *HTTP semantics* (RFC 9110).
RFC Editor. https://doi.org/10.17487/RFC9110

Thomson, M., & Nottingham, M. (2022). *HTTP/1.1* (RFC 9112). RFC Editor.
https://doi.org/10.17487/RFC9112

MITRE. (2026). *CWE-400: Uncontrolled resource consumption*. Common Weakness
Enumeration. https://cwe.mitre.org/data/definitions/400.html
