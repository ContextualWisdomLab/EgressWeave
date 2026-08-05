# Finite connection-pool resource limits

## Decision

EgressWeave makes connection-pool allocation an immutable, provider-neutral
policy dependency. `EgressConnectionPolicy` defines three reviewed values for
each synchronous or asynchronous pinned HTTPCore pool:

- `max_connections`: a positive finite maximum for simultaneous open or
  in-progress connections;
- `max_keepalive_connections`: a finite non-negative maximum for reusable idle
  connections, never greater than `max_connections`; and
- `keepalive_expiry_seconds`: a finite non-negative idle-retention window.

The defaults preserve HTTPX's documented ordinary limits of 100 total
connections, 20 idle keep-alive connections, and five seconds of idle retention.
Integrations can inject stricter limits without replacing transport code. A zero
idle capacity or zero idle expiry is valid when an operator intentionally wants
no idle socket retention; a zero total capacity is rejected because it would not
form a usable outbound client contract.

Counts accept exact integers or ASCII decimal strings for environment-variable
configuration. Booleans, fractional values, non-ASCII digits, empty text,
negative counts, non-finite expiry values, and contradictory idle/total values
fail during trusted policy construction. `None` is not accepted, so callers
cannot silently select HTTPCore's unbounded mode.

## Security and acquisition rationale

An exact destination allowlist limits *where* the client can connect, but it does
not limit how many sockets caller activity can allocate or how long idle sockets
remain retained. A compromised caller or approved upstream can therefore still
amplify file-descriptor, ephemeral-port, memory, and connection-state pressure.
CWE-770 recommends defining explicit minimum and maximum resource expectations,
while CWE-400 recommends limiting resources an untrusted actor can cause a
system to consume. Binding finite pool cardinality and retention to the same
immutable egress policy closes that operational gap.

The normalized connection policy participates in deterministic decision-evidence
fingerprints. Audit systems can therefore detect policy drift without recording
connection targets, resolved addresses, request paths, credentials, or response
data.

## Enforcement invariants

1. Both public `EgressPolicy` constructors accept the same immutable
   `connection_policy` dependency.
2. Both pinned transports pass only the normalized policy values to HTTPCore.
3. No caller request can replace or disable pool limits after client creation.
4. Idle capacity never exceeds total capacity.
5. Invalid or unbounded configuration fails before DNS resolution or network I/O.
6. Defaults preserve the dependency's documented bounded behavior.
7. Synchronous and asynchronous pool internals, policy fingerprints, validation
   boundaries, public exports, and every production branch are covered offline.

## References

Encode OSS. (n.d.). *Resource limits*. HTTPX.
https://www.python-httpx.org/advanced/resource-limits/

MITRE. (2026a). *CWE-400: Uncontrolled resource consumption* (Version 4.20).
Common Weakness Enumeration.
https://cwe.mitre.org/data/definitions/400.html

MITRE. (2026b). *CWE-770: Allocation of resources without limits or throttling*
(Version 4.20). Common Weakness Enumeration.
https://cwe.mitre.org/data/definitions/770.html
