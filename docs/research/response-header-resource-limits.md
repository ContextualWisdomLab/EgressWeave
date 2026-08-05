# Finite response-header resource limits

## Decision

EgressWeave applies two independent limits to every decoded response field
section before an `httpx.Response` is returned:

- `max_response_header_fields`, defaulting to **100**, counts every field line
  independently, including repeated `Set-Cookie` fields.
- `max_response_header_bytes`, defaulting to **65,536 bytes**, sums the exact
  decoded bytes in each field name and value.

Both settings accept positive integers or positive ASCII decimal strings during
trusted policy construction. Zero, negative, boolean, fractional, signed,
non-ASCII, empty, and unrelated values fail closed before DNS or network I/O.
The limits participate in decision-evidence policy fingerprints so an operator
can detect configuration drift without recording response metadata.

## Standards basis

HTTP does not prescribe a universal field-line or field-section size. RFC 9110
section 5.4 explicitly recognizes implementation-specific recipient limits and
permits clients to reject received fields they are unwilling to process. A
security library therefore needs documented finite defaults rather than relying
on a downstream parser's platform-dependent ceiling.

MITRE classifies uncontrolled resource consumption as CWE-400 and more
specifically identifies allocation without limits or throttling as CWE-770.
OWASP likewise recommends limiting message size, memory, connections, and other
resources to preserve availability. An allowlisted authority remains capable of
being compromised or returning attacker-controlled metadata, so exact-authority
egress controls do not remove this resource-exhaustion risk.

## Operational boundary

The limits are enforced on the complete decoded header sequence returned by
HTTPCore, before EgressWeave constructs a caller-visible HTTPX response. The
field-count budget bounds fanout. The byte budget counts field-name and
field-value bytes, while the count budget separately bounds per-field structural
overhead. Repeated fields are not coalesced because doing so can change semantics,
particularly for `Set-Cookie`.

A denial closes the underlying synchronous or asynchronous response stream so
the pooled connection is released. Cleanup failures are suppressed behind the
same generic `EgressNotAllowedError` boundary; arbitrary peer-controlled or
transport-controlled exception text is not attached as a cause or context.
Malformed non-byte downstream metadata and malformed field tuples also fail
closed through that generic boundary.

This control intentionally operates after the protocol parser. It bounds what
EgressWeave retains and exposes, but it cannot reduce memory already consumed by
an HTTP parser before HTTPCore produces decoded fields. Deployment layers must
therefore retain finite parser, proxy, ingress, and socket limits as defense in
depth. EgressWeave's defaults are client policy, not a claim that 100 fields or
64 KiB is universally appropriate; integrations with stricter contracts should
configure lower positive values.

## References

Fielding, R. T., Nottingham, M., & Reschke, J. (2022). *HTTP semantics*
(RFC 9110). RFC Editor. https://doi.org/10.17487/RFC9110

MITRE. (2026). *CWE-400: Uncontrolled resource consumption* (CWE Version
4.20). https://cwe.mitre.org/data/definitions/400.html

MITRE. (2026). *CWE-770: Allocation of resources without limits or throttling*
(CWE Version 4.20). https://cwe.mitre.org/data/definitions/770.html

OWASP Foundation. (n.d.). *Web service security cheat sheet*. OWASP Cheat
Sheet Series. Retrieved August 5, 2026, from
https://cheatsheetseries.owasp.org/cheatsheets/Web_Service_Security_Cheat_Sheet.html
