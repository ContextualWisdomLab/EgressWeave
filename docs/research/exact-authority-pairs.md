# Exact host-and-port authority pairs

## Decision

EgressWeave authorizes complete normalized `(hostname, port)` pairs. The public
`EgressPolicy.allowed_hosts` and `allowed_ports` sets remain available as
projections for compatibility and operator inspection, but runtime URL
validation uses `allowed_authorities` as the authoritative policy boundary.

Use `EgressPolicy.from_hosts(...)` when the intended policy is unambiguous:

- several hostnames that all share one port; or
- one hostname that intentionally exposes several ports.

When both axes vary, use `EgressPolicy.from_authorities(...)` and enumerate each
permitted destination explicitly. A `from_hosts(...)` call containing several
hosts and several ports fails during policy construction rather than silently
authorizing the Cartesian product.

```python
from egressweave import EgressPolicy

policy = EgressPolicy.from_authorities(
    [
        ("api.example.com", 443),
        ("admin.example.com", 8443),
    ]
)
```

This policy authorizes `api.example.com:443` and
`admin.example.com:8443`. It does not authorize `api.example.com:8443` or
`admin.example.com:443`.

## Security rationale

RFC 9110 defines an HTTP origin by the scheme, host, and port. Services on two
ports of the same host are therefore distinct authorities and can expose very
different capabilities. A policy represented only as a host set and a port set
cannot preserve which port was intended for which host. Taking the Cartesian
product creates permissions the operator did not write down.

For example, an application might require a public API on
`api.example.com:443` and an administrative endpoint on
`admin.example.com:8443`. A global host set combined with a global port set also
permits the public hostname on the administrative port. If that listener exists,
the policy has widened from two reviewed destinations to four possible
destinations.

Exact authority pairs close this gap before DNS resolution. A rejected
cross-pair cannot trigger a resolver lookup, reach TLS setup, or enter the
connection pool. The existing address validation, DNS pinning, SNI binding,
request-target checks, HTTP-method policy, response limits, and generic
non-leaking error boundary continue to apply after a pair is authorized.

## Canonicalization and validation

Each authority entry is a two-item tuple. EgressWeave deliberately does not
parse a colon-delimited string, because a structured pair avoids userinfo,
IPv6-literal, empty-port, and delimiter ambiguity.

The hostname uses the existing UTS #46 non-transitional IDNA and STD3
canonicalization. The port uses the existing positive integer or ASCII decimal
normalization and must be between 1 and 65535. Duplicate authorities collapse
after normalization. Wildcards, URL syntax, credentials, IP literals, malformed
IDNA labels, booleans, port zero, and out-of-range ports fail at policy
construction.

Direct dataclass construction that supplies `allowed_authorities` must also
supply matching `allowed_hosts` and `allowed_ports` projections. Contradictory
policy state fails immediately instead of leaving introspection and enforcement
with different meanings.

## Compatibility

This is an intentional pre-1.0 secure-default tightening.

Existing configurations continue to work when:

- all hosts use the default port 443;
- several hosts share one explicitly configured port; or
- one host intentionally permits several ports.

A configuration with several hosts and several ports must migrate to explicit
pairs. This migration can reduce permissions but does not add a network path.
Applications should enumerate only authorities that their deployment genuinely
uses and keep separate policies for integrations with different methods,
response budgets, trust levels, or lifecycle ownership.

## References

Fielding, R., Nottingham, M., & Reschke, J. (2022). *HTTP semantics*
(RFC 9110). RFC Editor. https://doi.org/10.17487/RFC9110

OWASP Foundation. (n.d.). *Server-side request forgery prevention cheat sheet*.
OWASP Cheat Sheet Series.
https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html

OWASP Foundation. (2021). *A10:2021 — Server-side request forgery (SSRF)*.
OWASP Top 10.
https://owasp.org/Top10/2021/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/
