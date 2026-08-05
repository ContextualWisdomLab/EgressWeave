# Bounded DNS candidates and staggered pinned connection attempts

## Decision

EgressWeave accepts at most `EgressPolicy.max_resolved_addresses` unique,
validated addresses from one platform DNS result. The default is 16. Duplicate
resolver rows collapse without consuming additional capacity, the original
resolver preference order is preserved, and a result containing more unique
addresses fails closed with the generic policy error. It is not silently
truncated because truncation could hide materially different resolver state
from operators and downstream audit correlation.

The asynchronous pinned transport starts one validated address immediately and
starts each later candidate only after a 250 ms delay while earlier attempts are
still pending. The first successful stream wins; every losing task is cancelled
and awaited. A later candidate receives only the connection-timeout budget that
remains, so staggered racing does not multiply the caller's timeout. The
synchronous transport remains sequential.

The cardinality policy is re-applied whenever a signed validation result enters
a pinned transport or audit-evidence builder. A result created under a wider
policy therefore cannot bypass a stricter current policy. The normalized limit
is included in the policy fingerprint so operational correlation detects DNS
candidate-budget drift without recording any resolved address.

## Standards basis

RFC 8305 advises clients not to start every connection simultaneously because
doing so creates unreasonable network load. It recommends starting one
candidate first, adding later attempts one at a time, cancelling losers after
the first success, and using 250 ms as the default Connection Attempt Delay.
The RFC assumes an ordered address list but does not require accepting an
unbounded list supplied by a resolver.

CWE-400 identifies failure to constrain resource allocation as uncontrolled
resource consumption and recommends limiting resources according to expected
operating requirements. A DNS response can contain repeated or numerous address
records. Python's `socket.getaddrinfo()` exposes those results as a sequence of
address tuples; EgressWeave validates every candidate and then applies a finite
unique-address boundary before retaining pinned state or scheduling connection
attempts.

A limit of 16 is intentionally conservative for API-client use while preserving
ordinary multi-address IPv4/IPv6 deployments. Integrations with a demonstrated
need for a wider set can inject a larger positive integer or ASCII decimal
string. Zero, negative, boolean, fractional, signed, empty, non-ASCII, and other
malformed values fail at policy construction rather than disabling the control.

## Threat and reliability model

A hostname can legitimately resolve to several IPv4 and IPv6 addresses. Without
a candidate cap, a large or compromised DNS answer can increase retained memory,
validation work, asynchronous task creation, and sequential or staggered TCP
attempts. Staggering alone limits concurrency but does not bound total work.

The combined controls preserve these invariants:

1. every address comes from the bounded validation resolver;
2. every unique address is validated before it is retained;
3. resolver preference order is preserved and duplicate rows collapse;
4. an over-limit unique set fails closed instead of being partially accepted;
5. every retained address is revalidated immediately before connect;
6. the hostname and port must still match the validated authority;
7. the first successful asynchronous stream is returned and every loser is
   cancelled and awaited; and
8. the caller's connection-timeout budget is shared across attempts.

## References

MITRE. (2026). *CWE-400: Uncontrolled resource consumption* (CWE Version 4.20).
https://cwe.mitre.org/data/definitions/400.html

Python Software Foundation. (2026). *socket—Low-level networking interface*.
Python 3.13 documentation.
https://docs.python.org/3/library/socket.html#socket.getaddrinfo

Schinazi, D., & Pauly, T. (2017). *Happy Eyeballs Version 2: Better connectivity
using concurrency* (RFC 8305). Internet Engineering Task Force.
https://www.rfc-editor.org/rfc/rfc8305
