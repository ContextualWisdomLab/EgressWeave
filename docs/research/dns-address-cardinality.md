# Finite DNS destination-address cardinality

## Decision

Every `EgressPolicy` defines a finite `max_resolved_addresses` budget. The
secure default is 32 unique validated IP destinations per resolver result. The
field accepts a positive integer or an ASCII decimal string so deployment
configuration can stay explicit; zero, negative, boolean, fractional, empty,
signed, non-ASCII, and malformed values fail during policy construction.

Synchronous and asynchronous validation apply the same rule. EgressWeave
preserves resolver order, validates each candidate before it can be retained,
and deduplicates canonical IP addresses. Duplicate platform rows do not consume
the allowance. The first additional unique valid address raises the generic
`EgressNotAllowedError` and rejects the complete DNS result. EgressWeave never
silently truncates an accepted candidate list.

Signed `ValidatedEgressURL` objects are checked again against the current
policy. A result created under a larger address budget therefore cannot be
reused after an integration adopts a tighter budget. The normalized value is
also included in the safe decision-evidence policy fingerprint, making resource
policy drift audit-visible without exposing resolved addresses.

## Threat and resource boundary

DNS answer sections can contain a variable number of resource records (RFC
1035), and Python's `socket.getaddrinfo()` exposes destination candidates as a
list. Before this control, every unique public destination could become:

1. an `ipaddress` validation operation;
2. an entry retained in the signed validation result;
3. input to integrity hashing and later policy revalidation; and
4. a possible synchronous or staggered asynchronous connection attempt.

An allowlisted but compromised or attacker-operated DNS authority could thus
amplify one outbound validation into unbounded Python-side memory, CPU, and
connection-candidate work (CWE-400). Timeout and global resolver-worker limits
bound duration and concurrent lookups but do not bound the size of one returned
candidate set. The cardinality budget closes that independent dimension.

The control begins after the operating-system resolver returns. It bounds the
unique validated tuple, EgressWeave integrity payload, and EgressWeave
connection candidates. It cannot bound DNS packet processing, resolver-cache
state, native `getaddrinfo()` allocations, or work performed inside the
operating system or a configured resolver. Operators needing those guarantees
must also configure resolver, operating-system, and network-layer controls.

## Why reject instead of truncate

RFC 8305 requires the connection algorithm to preserve an ordered candidate
list involving all addresses received at that point and to stagger attempts to
avoid unreasonable network load. Taking only the first *N* records could
silently remove one address family, make resolver ordering a hidden security
policy, or create inconsistent behavior across platforms. EgressWeave therefore
accepts the complete unique set only when it fits the explicit policy and
otherwise fails closed before transport construction.

The default of 32 is an implementation-defined resource ceiling, not a limit
specified by DNS or Happy Eyeballs standards. It is intentionally configurable
for reviewed multi-homed services while remaining finite in every policy.

## Verification contract

Deterministic offline tests establish that:

- both public policy constructors normalize the same field;
- invalid configuration fails fast with field-specific operator errors;
- exact-limit candidate sets preserve resolver order;
- duplicate rows do not consume the unique-address allowance;
- synchronous and asynchronous over-limit results fail with the same generic
  runtime error;
- current-policy revalidation rejects a previously signed oversized set; and
- policies differing only in the DNS address budget produce different audit
  fingerprints.

## References

Mockapetris, P. (1987). *Domain names—Implementation and specification* (RFC
1035). RFC Editor. https://doi.org/10.17487/RFC1035

Python Software Foundation. (2026). *socket—Low-level networking interface*
(Python 3.14.6 documentation). https://docs.python.org/3/library/socket.html

Schinazi, D., & Pauly, T. (2017). *Happy Eyeballs Version 2: Better connectivity
using concurrency* (RFC 8305). RFC Editor. https://doi.org/10.17487/RFC8305

The MITRE Corporation. (2026). *CWE-400: Uncontrolled resource consumption*
(Version 4.20). Common Weakness Enumeration.
https://cwe.mitre.org/data/definitions/400.html
