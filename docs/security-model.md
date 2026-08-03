# Security model

EgressWeave prevents an application-controlled outbound URL from escaping an explicit hostname policy through SSRF, DNS rebinding, authority drift, redirects, environment proxies, or Unix sockets. This document defines the boundary precisely so integrators do not mistake transport safety for complete application authorization.

## Protected assets

Typical protected assets are cloud metadata services, loopback listeners, RFC 1918 and RFC 4193 networks, link-local services, control-plane endpoints, and any destination not present in the application's exact hostname allowlist.

## Attacker capabilities

The model assumes an attacker may control the candidate URL, path, request data, and low-level HTTPX request extensions; operate an allowlisted DNS zone; return multiple A or AAAA records; change DNS answers after validation; supply unusual URL syntax; attempt absolute-target, `Host`, or TLS Server Name Indication (SNI) authority drift; and cause individual validated addresses to fail during connection establishment.

The attacker is not assumed to control the embedding application's Python process, `EgressPolicy`, trust store, operating system, installed EgressWeave package, or the legitimate remote service behind an allowlisted hostname. Code execution inside the process can bypass any in-process policy.

## Enforced invariants

For a non-local target, EgressWeave:

1. accepts only `https` URLs without embedded credentials, query strings, fragments, backslashes, or ASCII control characters;
2. accepts only exact hostname entries when `EgressPolicy` is constructed, rejects wildcard, URL/authority, whitespace/control, non-string, and IP-literal forms, and then requires an exact normalized hostname match at request validation;
3. resolves every address returned by the system resolver and rejects the complete target if any address is not globally routable;
4. signs the resulting `ValidatedEgressURL` with a process-local integrity key and revalidates its URL, hostname, port, address shape, signature, and address scope before transport construction;
5. connects only to the validated address set while preserving the original hostname for certificate verification and TLS Server Name Indication;
6. rejects request scheme, user information, hostname, effective-port, or caller-supplied SNI drift before the request reaches the connection pool;
7. replaces any caller-supplied `Host` header and binds the forwarded `sni_hostname` extension to the validated authority;
8. disables redirects and environment-derived proxy configuration;
9. refuses Unix-domain sockets; and
10. returns a deny-all transport when client construction receives no non-empty base URL, so missing or optional configuration cannot silently create unrestricted egress.

A failure is surfaced as the generic `EgressNotAllowedError` where validation policy is involved so rejection details do not become a policy oracle. Invalid trusted policy configuration raises `ValueError` or `TypeError` during construction so deterministic operator mistakes are discovered before request handling begins.

## Local-development exception

`allow_local=True` is intentionally narrow:

- `localhost`, `localhost.localdomain`, `127.0.0.1`, and `::1` may resolve only to loopback addresses;
- an explicitly allowlisted single-label container hostname may resolve only to loopback, RFC 1918 IPv4, or RFC 4193 IPv6 unique-local space; and
- dotted remote names never inherit the local exception.

Do not enable this option in production merely to work around DNS or routing configuration. Separate production and development policies.

## Trust boundaries

EgressWeave relies on:

- the embedding application to construct and protect the correct `EgressPolicy`;
- the operating system resolver to return syntactically valid address records;
- the operating system network stack and configured CA trust store;
- the constrained `httpx` and `httpcore` versions declared by the package; and
- the allowlisted remote service to enforce its own authentication and authorization.

DNS pinning prevents a later DNS answer from changing the connection destination. It does not make the resolver available, authentic, or confidential. Applications should apply their own request deadlines, cancellation, concurrency limits, and circuit breakers.

## Explicit non-goals

EgressWeave does not:

- authorize paths, methods, request bodies, or query parameters on an allowlisted service;
- prevent data exfiltration to a legitimately allowlisted but malicious or compromised service;
- inspect response bodies, enforce content types, scan malware, or cap response size;
- validate application credentials, API keys, OAuth scopes, or tenant boundaries;
- replace a network firewall, service mesh egress gateway, sandbox, or operating-system isolation;
- follow redirects safely across authorities—redirect following is disabled instead; or
- support arbitrary HTTP proxies, custom transports, Unix sockets, or caller-selected destination IP addresses.

## Integration requirements

Use a distinct policy for each trust domain and keep the allowlist as small as possible. Supply bare hostnames only—never schemes, credentials, ports, paths, wildcards, or IP literals—and construct the policy during application startup so configuration errors stop deployment before traffic is served. Construct clients once per validated authority, close them deterministically, set application-appropriate HTTPX timeouts, and never fall back to an unguarded HTTP client after `EgressNotAllowedError`.

An empty or absent base URL is not an authorization signal. The builder returns a deny-all client in that state; applications should treat `normalized_url is None` as disabled configuration and must not replace the returned client with a generic HTTPX client.

Treat changes to `httpx`, `httpcore`, Python URL parsing, IP classification, resolver behavior, or local-address policy as security-sensitive. Re-run the complete transport and validation suite before widening the supported dependency range.

## Security regression expectations

A security fix should include a deterministic, offline regression test that fails before the fix and covers both synchronous and asynchronous paths when the invariant is shared. Tests must not depend on public DNS or external services. Release notes should identify the fixed version and whether the change is behavior tightening or a compatibility change.
