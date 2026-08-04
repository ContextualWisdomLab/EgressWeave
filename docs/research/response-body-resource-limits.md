# Bounded response-body consumption

## Decision

Every pinned client applies a finite decoded response-body budget from
`EgressPolicy.max_response_bytes`. The secure default is 16 MiB. A specific
integration may set another positive byte count, including a decimal string from
an environment variable, but zero, negative, boolean, fractional, non-ASCII, or
otherwise malformed values fail at policy construction.

The control is enforced at two layers:

1. A body-bearing response with an unsafe `Content-Length` is rejected before a
   caller-visible `httpx.Response` is returned. Duplicate, comma-joined, signed,
   malformed, or over-budget lengths fail through the generic
   `EgressNotAllowedError` boundary and the source stream is closed.
2. Every decoded body chunk is counted while it is consumed. This authoritative
   check covers chunked, close-delimited, missing-length, and dishonestly
   under-declared responses. The first chunk that would exceed the policy budget
   is not exposed to the caller; the source stream is closed and the same generic
   policy error is raised.

Responses to `HEAD`, informational responses, `204 No Content`, and
`304 Not Modified` are treated as bodyless. Their `Content-Length` fields can
represent selected-representation metadata rather than bytes carried in that
message and therefore are not compared with the consumption budget.

## Threat model

Destination allowlisting and DNS pinning establish *where* a request may go.
They do not establish that the allowlisted peer will remain trustworthy or
return a bounded amount of data. A compromised vendor API, attacker-controlled
allowed tenant endpoint, decompression expansion, or simple upstream defect can
keep delivering bytes until process memory, disk-backed buffering, connection
capacity, or worker time is exhausted. This is an availability failure in the
CWE-400 uncontrolled-resource-consumption family.

A header-only check is insufficient because HTTP permits responses whose body
length is determined by transfer coding or connection closure, and a hostile
peer can lie about `Content-Length`. Conversely, a streaming-only check delays a
known failure and needlessly consumes network and pool resources. EgressWeave
therefore performs both the early metadata check and the decoded-stream count.

## Compatibility

This is an intentional pre-1.0 secure-default tightening. Existing ordinary JSON
API integrations remain under the 16 MiB default without configuration changes.
Integrations that legitimately download larger artifacts must set a bounded,
integration-specific `max_response_bytes` value. EgressWeave does not provide an
unlimited sentinel because an accidental configuration change must not silently
remove the resource boundary.

## References

Fielding, R., Nottingham, M., & Reschke, J. (2022). *HTTP semantics* (RFC 9110).
RFC Editor. https://doi.org/10.17487/RFC9110

Thomson, M., & Nottingham, M. (2022). *HTTP/1.1* (RFC 9112). RFC Editor.
https://doi.org/10.17487/RFC9112

MITRE. (2026). *CWE-400: Uncontrolled resource consumption*. Common Weakness
Enumeration. https://cwe.mitre.org/data/definitions/400.html
