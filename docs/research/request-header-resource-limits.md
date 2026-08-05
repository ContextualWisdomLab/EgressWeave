# Finite outbound request-header resource limits

## Decision

EgressWeave applies two independent limits to the final outbound HTTP field
section before a request reaches HTTPCore's connection pool:

- `max_request_header_fields`, defaulting to **100**, counts every field line
  independently.
- `max_request_header_bytes`, defaulting to **65,536 bytes**, sums the exact
  bytes in each final field name and value.

Both settings accept positive integers or positive ASCII decimal strings during
trusted policy construction. Zero, negative, boolean, fractional, signed,
non-ASCII, empty, and unrelated values fail closed before DNS or network I/O.
The limits participate in decision-evidence policy fingerprints so operators can
detect configuration drift without recording credentials or request metadata.

## Standards basis

HTTP does not define one universal field-line or field-section limit. RFC 9110
section 5.4 explicitly permits implementation-specific limits and warns that
processing oversized request fields while ignoring part of them can increase
exposure to request-smuggling attacks. A security transport therefore needs
finite, documented client-side limits instead of delegating arbitrary metadata
fanout to downstream protocol implementations.

MITRE classifies uncontrolled resource consumption as CWE-400 and more
specifically identifies allocation without limits or throttling as CWE-770.
OWASP likewise recommends finite message-size and resource limits to preserve
availability. Exact-authority destination controls do not bound caller-supplied
credentials, cookies, tracing fields, or custom metadata, so request-header
budgets remain a separate defense.

## Operational boundary

The limits are enforced after EgressWeave validates raw field syntax, rejects
ambiguous framing and protocol-switching fields, removes caller-supplied `Host`
and `Accept-Encoding`, and appends the trusted authority plus
`Accept-Encoding: identity`. The final fields actually delegated to HTTPCore are
therefore counted, including EgressWeave's two trusted fields. Repeated fields
count independently; the byte budget counts field-name and field-value bytes,
while the field-count budget separately bounds structural overhead.

A denial occurs before connection-pool dispatch and closes the caller's
synchronous or asynchronous request stream. Cleanup failures are suppressed
behind the same generic `EgressNotAllowedError` boundary; arbitrary
caller-controlled exception text is not attached as a cause. Malformed non-byte
metadata and iterators that fail while yielding fields also fail closed through
that generic boundary.

This control bounds what EgressWeave dispatches, but HTTPX may already have
materialized caller headers before the transport receives a request. Application
layers must therefore retain their own input, framework, proxy, and memory limits
as defense in depth. The defaults are a general API-client policy, not a claim
that 100 fields or 64 KiB is universally appropriate. Integrations with narrower
contracts should configure lower positive values.

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
