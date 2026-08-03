# Exact authorization for local-development names

EgressWeave treats local development as a deliberate widening of address scope,
not as an implicit hostname grant.

## Security rationale

The OWASP SSRF Prevention Cheat Sheet distinguishes deployments that can name
identified trusted applications and recommends checking every requested domain
against that explicit allowlist. Local services are particularly sensitive SSRF
targets because they commonly expose unauthenticated administration, debugging,
or metadata interfaces that are unreachable from outside the host.

RFC 6761 reserves `localhost.` and names beneath it for loopback resolution. That
special resolution behavior defines where the name should resolve; it does not
mean every application should authorize access to every local listener. The
application's egress policy must therefore make two independent decisions:

1. whether the exact hostname is authorized; and
2. whether local address classes are authorized for that hostname.

EgressWeave now requires both. `allow_local=True` permits an explicitly
allowlisted `localhost` or `localhost.localdomain` name to resolve to loopback,
but it does not add either name to `allowed_hosts`. Loopback IP-literal URLs
remain forbidden so all local access retains a reviewable hostname identity.
Container aliases continue to require an exact single-label allowlist entry and
may resolve only to loopback, RFC 1918 IPv4, or RFC 4193 IPv6 unique-local
space.

This closes a least-privilege gap where a policy intended only for an allowlisted
container such as `ollama` could also reach an unrelated listener on
`localhost` when both services used the same authorized port.

## Primary references

- [OWASP SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
- [RFC 6761, section 6.3: Domain Name Reservation Considerations for `localhost.`](https://www.rfc-editor.org/rfc/rfc6761.html#section-6.3)
- [CWE-918: Server-Side Request Forgery](https://cwe.mitre.org/data/definitions/918.html)
