# Finite outbound request-target resource limits

## Decision

EgressWeave limits the exact origin-form request target delegated to HTTPCore.
`EgressPolicy.max_request_target_bytes` defaults to 8,192 bytes and is evaluated
against HTTPX's percent-encoded `request.url.raw_path`, including the optional
query component. A target at the configured boundary is forwarded unchanged; a
target one byte over the boundary is rejected before connection-pool dispatch.
The transport never truncates or re-encodes the target because either operation
can change the selected resource.

Both public policy constructors accept a positive integer or an ASCII decimal
string. Booleans, fractional values, signed strings, non-ASCII digits, zero,
negative values, empty text, and unrelated objects fail during trusted policy
construction. The normalized budget participates in deterministic policy and
decision fingerprints without recording the request path or query.

## Standards basis

HTTP defines a request target as the identifier of the resource to which the
method applies. Direct origin requests use the origin form: an absolute path
followed by an optional query. RFC 9110 recommends support for URI protocol
elements of at least 8,000 octets, and RFC 9112 recommends support for request
lines of at least 8,000 octets. RFC 9112 also requires a recipient that refuses
to parse a longer request target to return `414 URI Too Long`.

Those interoperability minima do not require a security-sensitive outbound
client to accept an unbounded caller-controlled target. The EgressWeave default
uses 8 KiB, slightly above the 8,000-octet recommendation, while allowing each
integration to select a larger finite value when its API contract requires one.
The limit is applied on the client side before network allocation rather than
relying on an allowlisted server to reject the request.

CWE-400 describes failures to control consumption of limited resources and
recommends architectural limits on resources an untrusted actor can cause a
system to expend. An allowlisted authority constrains destination identity but
does not constrain attacker-controlled path or query growth. A finite target
budget therefore complements authority, DNS candidate, header, body, timeout,
and response limits.

## Enforcement invariants

1. The measured value is the exact `bytes` object that becomes
   `httpcore.URL.target`.
2. Percent-encoded path and query bytes are counted without decoding,
   normalization, or truncation.
3. Non-exact byte values and byte subclasses are rejected to avoid invoking
   alternate buffer or conversion behavior at the trust boundary.
4. Rejection occurs before synchronous or asynchronous pool dispatch.
5. A denied request stream is closed; cleanup failures are masked behind a new
   generic `EgressNotAllowedError` so attacker-controlled exception text does not
   cross the policy boundary.
6. The normalized limit is included in audit fingerprints, while target content
   is omitted from evidence.
7. Boundary, over-boundary, malformed-configuration, percent-encoding,
   fingerprint-drift, pre-dispatch, and cleanup behavior are covered by offline
   synchronous and asynchronous regression tests.

## References

Fielding, R., Nottingham, M., & Reschke, J. (2022a). *HTTP semantics* (RFC
9110). Internet Engineering Task Force. https://www.rfc-editor.org/rfc/rfc9110

Fielding, R., Nottingham, M., & Reschke, J. (2022b). *HTTP/1.1* (RFC 9112).
Internet Engineering Task Force. https://www.rfc-editor.org/rfc/rfc9112

MITRE Corporation. (2026). *CWE-400: Uncontrolled resource consumption*
(Version 4.20). Common Weakness Enumeration.
https://cwe.mitre.org/data/definitions/400.html
