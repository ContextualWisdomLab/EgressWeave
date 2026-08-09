# DNS resolution resource bounds

## Scope

EgressWeave resolves an already-authorized canonical `(hostname, port)` before a
pinned transport can connect. DNS remains an untrusted and potentially slow
platform dependency: callers need a finite wait, the process needs a finite
resolver-worker budget, and a slow authority must not multiply background work
merely because several requests arrive together.

This note records the exact runtime boundary implemented by the DNS validation
layer. It does not make DNS an authorization source and does not replace the
existing all-address scope checks, exact authority policy, transport pinning, or
per-connect address revalidation.

## Implemented boundary

The process retains one finite global resolver-worker pool. When overlapping
validations target the same exact authority, they join one live **in-flight**
resolver operation keyed by canonical `(hostname, port)` instead of creating a
new platform resolver thread for every caller.

The sharing boundary is intentionally live-only:

- the registry **never caches a completed DNS result**;
- the entry is removed as soon as the worker completes and current waiters are
  released;
- a later validation therefore starts a fresh lookup, preserving the product's
  DNS rebinding freshness model instead of converting single-flight into a DNS
  cache;
- the worker publishes only raw address strings; **each caller retains its own**
  finite `dns_timeout_seconds` deadline and independently applies all-address
  classification, local-development rules, deduplication, and its own
  `max_resolved_addresses` ceiling;
- empty answers, capacity exhaustion, worker-start failure, resolver failure,
  caller deadline exhaustion, and incomplete shared outcomes all fail closed;
- unexpected resolver exceptions are normalized to the public generic denial
  without retaining dependency-controlled `__cause__` or `__context__` text.

This arrangement reduces same-authority amplification without weakening policy
isolation. A permissive caller cannot donate its larger address cardinality or
local-address scope to a stricter caller that happened to share the same raw DNS
lookup.

## Residual platform limitation

The standard-library resolver path ultimately calls `socket.getaddrinfo`, whose
work can block in the operating-system or C-library resolver. EgressWeave runs
that call on a daemon thread so the caller can stop waiting at its configured
deadline, but Python does not provide a safe general operation for forcibly
terminating arbitrary already-running thread work. EgressWeave therefore
**cannot safely cancel** an already-running platform `socket.getaddrinfo` call.

A timed-out resolver worker may remain alive and keep one global resolver slot
until the platform call returns. Single-flight prevents repeated callers for one
slow authority from consuming additional slots, but distinct stalled
authorities can still occupy the finite global pool. Once capacity is exhausted,
new validations fail closed rather than creating unbounded resolver work. The
caller timeout consequently bounds caller waiting time; it does not claim to
bound the operating-system resolver's lifetime.

This residual is deliberate. The package does not interrupt Python threads,
ship a recursive DNS resolver, silently detach unbounded work, or persist a
completed result merely to avoid another lookup. Those alternatives would
introduce larger correctness, portability, security, or DNS rebinding risks.

## Security interpretation

The original failure mode is an asymmetric resource-consumption problem: a
small number of repeated validations could leave disproportionate live resolver
work after the initiating callers had already failed. CWE-405 describes this
amplification family, while CWE-410 describes exhaustion of a finite resource
pool and CWE-400 is the broader uncontrolled-resource-consumption class. The
runtime fix both meters the global resource and collapses duplicate
same-authority live work.

These CWE entries are diagnostic taxonomy, not proof of vulnerability severity.
CWE-400 is a high-level class and MITRE discourages mapping to overly broad
entries when a more specific weakness is available.

## Operational expectations

Host applications and operators should preserve these assumptions:

1. A DNS timeout is a caller-wait bound, not a guarantee that the platform
   resolver thread has terminated.
2. Repeated generic DNS denials or resolver-capacity pressure should be measured
   outside the core library using purpose-limited counters; raw candidate URLs,
   credentials, resolved IP addresses, and resolver exception text should not be
   added to default telemetry.
3. Resolver availability, operating-system DNS configuration, recursive-server
   behavior, and network reachability remain host/platform responsibilities.
4. EgressWeave must continue to re-resolve after a completed flight. Persisting
   completed DNS results would change the reviewed DNS rebinding and freshness
   boundary and requires a separate architecture decision.
5. A future resolver implementation must preserve exact authority identity,
   finite concurrency, per-caller policy validation, generic failure behavior,
   and fresh post-completion resolution before it can replace this boundary.

RFC 8305 treats hostname resolution and subsequent connection concurrency as
separate stages and explicitly accounts for DNS answers changing during
connection setup. EgressWeave does not claim RFC 8305 defines its single-flight
mechanism; the RFC is relevant because the live-only design avoids turning a
resource-control optimization into a persistent answer cache that would erase
fresh DNS observations.

## References

MITRE. (2026). *CWE-400: Uncontrolled resource consumption (Version 4.20)*.
https://cwe.mitre.org/data/definitions/400.html

MITRE. (2026). *CWE-405: Asymmetric resource consumption (amplification)
(Version 4.20)*. https://cwe.mitre.org/data/definitions/405.html

MITRE. (2026). *CWE-410: Insufficient resource pool (Version 4.20)*.
https://cwe.mitre.org/data/definitions/410.html

Python Software Foundation. (2026). *socket — Low-level networking interface
(Python 3.13.14 documentation)*. https://docs.python.org/3.13/library/socket.html

Python Software Foundation. (2026). *threading — Thread-based parallelism
(Python 3.13.14 documentation)*. https://docs.python.org/3.13/library/threading.html

Schinazi, D., & Pauly, T. (2017). *Happy Eyeballs Version 2: Better connectivity
using concurrency* (RFC 8305). RFC Editor. https://doi.org/10.17487/RFC8305
