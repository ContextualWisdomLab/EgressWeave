# Finite outbound connection-pool resource limits

## Decision

EgressWeave injects one immutable, provider-neutral
`EgressConnectionPoolPolicy` into every synchronous and asynchronous pinned
transport. The policy defaults to at most 100 total connections, 20 retained
idle connections, and a five-second idle keep-alive lifetime. Operators can set
smaller or larger finite values for a specific integration without importing
HTTPX private configuration or constructing an HTTPCore-specific object.

At trusted policy construction, `connection_pool_policy` must be the exact
`EgressConnectionPoolPolicy` type. Subclass polymorphism is not a supported
configuration extension mechanism because retaining a subclass would allow
later attribute dispatch to diverge from the finite capacities that were
reviewed and fingerprinted. Integrations that need different limits construct
an exact `EgressConnectionPoolPolicy` with different documented field values
instead. This boundary does not claim EgressWeave sandboxes arbitrary Python
code already executing inside the embedding process.

`max_connections` must be a positive integer or ASCII decimal string.
`max_keepalive_connections` may be zero to retain no idle connections but must
not exceed total capacity. `keepalive_expiry_seconds` must be a finite
non-negative real number and may be zero for immediate expiry. Booleans,
fractional counts, signed or non-ASCII count text, negative values, non-finite
expiry values, unrelated objects, and contradictory capacities fail during
trusted policy construction.

## Standards basis

RFC 9112 advises clients to limit simultaneous open connections to a server,
notes that every connection consumes server resources, and warns that excessive
parallel connections can create congestion or resemble denial-of-service
traffic. It intentionally does not prescribe one universal maximum because
appropriate capacity depends on the application. RFC 9112 also explains that
prompt connection closure enables allocated system resources to be reclaimed.

CWE-770 identifies allocating reusable resources without limits or throttling as
a denial-of-service weakness and recommends explicit administrator-definable
limits. A finite connection pool applies that control to sockets, TLS state,
buffers, and queued pool acquisition. The policy complements, rather than
replaces, request-phase timeouts, tenant quotas, workload concurrency, and
end-to-end cancellation.

HTTPX publicly documents finite defaults of 100 total connections, 20 keep-alive
connections, and five seconds of idle expiry. Earlier EgressWeave versions
implicitly copied those values from HTTPX's private `DEFAULT_LIMITS` object. The
new public policy preserves the prior default behavior while removing the
private-default dependency and making the limits stable, explicit, auditable,
and portable across standalone and modular integrations.

## Enforcement invariants

1. Both public `EgressPolicy` constructors accept the same immutable pool policy.
2. Trusted construction accepts only the exact `EgressConnectionPoolPolicy`
   type; subclasses are rejected before transport pool values are read.
3. Total connection capacity is always positive and finite.
4. Idle capacity is finite, may be zero, and cannot exceed total capacity.
5. Idle expiry is finite and non-negative; `None` cannot disable reclamation.
6. Synchronous and asynchronous HTTPCore pools receive the exact normalized
   values from the policy.
7. No transport imports HTTPX's private `DEFAULT_LIMITS` object.
8. The normalized pool policy participates in deterministic policy and decision
   fingerprints without recording live connection state.
9. Defaults, valid environment-style count text, invalid configuration,
   relational invariants, exact policy-type enforcement, sync/async delegation,
   public API exposure, and fingerprint drift are covered by offline regression
   tests with complete production statement and branch coverage.

## Operational guidance

Start with the finite defaults only when workload measurements justify them.
For a low-throughput webhook or administrative integration, a smaller total and
idle capacity reduces the blast radius of accidental fanout. For sustained
high-throughput APIs, increase limits only alongside upstream quotas, queue
backpressure, observability, and service-level evidence. Setting idle capacity
and expiry to zero disables reuse and is stricter for retention, but it can
increase connection and TLS-handshake cost; measure that trade-off rather than
assuming it is universally safer.

Applications that previously subclassed `EgressConnectionPoolPolicy` must
migrate to an exact instance and configure the supported finite fields directly.
The exact-type check runs during trusted startup, before a pool or request can
consume those values.

## References

Encode OSS Ltd. (n.d.). *Resource limits*. HTTPX. Retrieved August 5, 2026, from
https://www.python-httpx.org/advanced/resource-limits/

Fielding, R., Nottingham, M., & Reschke, J. (2022). *HTTP/1.1* (RFC 9112).
Internet Engineering Task Force. https://www.rfc-editor.org/rfc/rfc9112

MITRE Corporation. (2026). *CWE-770: Allocation of resources without limits or
throttling* (Version 4.20). Common Weakness Enumeration.
https://cwe.mitre.org/data/definitions/770.html
