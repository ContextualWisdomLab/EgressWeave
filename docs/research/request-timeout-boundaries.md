# Finite outbound request-timeout boundaries

## Decision

Every `EgressPolicy` carries an immutable `EgressTimeoutPolicy` with positive,
finite ceilings for connection establishment, response reads, request writes,
and connection-pool acquisition. Both pinned transports rewrite the low-level
HTTPX timeout extension immediately before HTTPCore dispatch:

- a missing timeout extension receives all four policy ceilings;
- a missing phase or `None` receives that phase's policy ceiling;
- a finite non-negative caller value is retained when it is stricter;
- a value above the ceiling is capped; and
- malformed maps, unknown keys, booleans, negative values, and non-finite
  numbers fail through the generic `EgressNotAllowedError` boundary.

Trusted policy construction accepts only the exact `EgressTimeoutPolicy` type.
Subclass polymorphism is not a supported extension mechanism because transport
binding later invokes `as_httpcore_timeout()`: a subclass could otherwise
replace that reviewed export path after startup validation. Applications that
previously supplied an `EgressTimeoutPolicy` subclass must migrate to an exact
instance configured through the documented immutable timeout fields. This
secure-default boundary keeps declarative values authoritative; it does not
claim to sandbox arbitrary trusted Python executing inside the embedding
process.

Policy maxima must be greater than zero. A request may still choose zero as an
immediate, stricter timeout. The sanitized mapping is detached from caller-owned
state and preserves unrelated safe extensions, including the validated TLS
server name and tracing callbacks.

## Why client defaults are insufficient

HTTPX provides finite defaults, but its documented request extension lets a
caller override connect, read, write, and pool timeout values. `None` disables a
timeout. A custom security transport that forwards this metadata unchanged
would therefore let request code weaken a resource boundary after destination
validation. Enforcing ceilings in the transport keeps the invariant attached to
the same unskippable boundary that verifies methods, authority, SNI, request
framing, and body size.

HTTPCore applies the four phases independently. Connect timeout covers TCP and
TLS establishment; read and write timeouts bound inactivity while transferring
chunks; pool timeout bounds waiting for a reusable connection. EgressWeave
preserves those native semantics and exception types.

## Operational boundary

Phase timeouts are inactivity limits, not a single end-to-end wall-clock
deadline. A peer can make progress just before each read or write deadline, and
application processing can occur outside the transport. Embedding services must
therefore combine EgressWeave with cancellation, job-level deadlines, bounded
concurrency, queue capacity, and tenant quotas.

The timeout policy is included in the deterministic policy fingerprint so an
operator can correlate audit evidence with the exact normalized resource
boundary without exposing request URLs, timing observations, credentials, or
response data.

## Security properties

- **Exact trusted policy type:** construction rejects timeout-policy subclasses
  before any later transport export can dynamically dispatch subclass code.
- **No timeout disablement:** missing and `None` phase values become finite.
- **No weaker override:** a request cannot exceed the immutable policy cap.
- **Stricter caller control:** non-negative values below the cap are retained.
- **Fail-closed metadata:** malformed extension shapes never reach HTTPCore.
- **Sync/async parity:** both transports call the same sanitizer immediately
  before constructing the HTTPCore request.
- **Audit-visible drift:** changing only a timeout ceiling changes both policy
  and decision fingerprints.

## References

Encode OSS. (n.d.). *Extensions*. HTTPX.
https://www.python-httpx.org/advanced/extensions/

Encode OSS. (n.d.). *Request extensions*. HTTPCore.
https://www.encode.io/httpcore/extensions/

Encode OSS. (n.d.). *Timeouts*. HTTPX.
https://www.python-httpx.org/advanced/timeouts/

Fielding, R., Nottingham, M., & Reschke, J. (2022). *HTTP/1.1* (RFC 9112),
section 9.5. RFC Editor.
https://www.rfc-editor.org/rfc/rfc9112.html#section-9.5

MITRE. (2026). *CWE-400: Uncontrolled resource consumption* (Version 4.20).
Common Weakness Enumeration.
https://cwe.mitre.org/data/definitions/400.html

Open Worldwide Application Security Project. (n.d.). *Denial of service cheat
sheet*. OWASP Cheat Sheet Series.
https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html
