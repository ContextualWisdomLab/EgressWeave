# Canonical request-method enforcement

## Decision

EgressWeave accepts a request at the pinned transport boundary only when its
method is the exact uppercase HTTP `token` authorized by `EgressPolicy`.
Operator-supplied policy configuration remains case- and surrounding-whitespace
normalized for environment-variable ergonomics, but the request itself is not
repaired or reinterpreted. Malformed, non-ASCII, whitespace-wrapped, or
alternate-case method text fails closed before HTTPCore dispatch.

## Standards basis

RFC 9110 section 9.1 defines `method = token`, states that method names are
case-sensitive, and notes that standardized methods are conventionally written
with uppercase US-ASCII letters. A method carrying spaces, tabs, line breaks, or
other non-token characters is therefore not a valid HTTP method. Treating a
trimmed or case-folded spelling as equivalent at the security boundary would
authorize one value while forwarding another.

CWE-444 describes security failures caused when HTTP agents interpret malformed
messages differently. Although request smuggling is most often demonstrated
with framing fields, the same fail-closed principle applies to request-line
control data: EgressWeave must not delegate an ambiguous method spelling to a
chain of HTTP parsers, gateways, and origin frameworks that may disagree about
its meaning.

## Threat model

HTTPX normally uppercases ordinary method input, but its low-level `Request`
constructor can preserve surrounding whitespace and other malformed strings.
EgressWeave transports are public HTTPX transport implementations and therefore
must validate the value they actually receive, rather than assume every caller
used a higher-level convenience API.

The transport now:

1. parses the received value with the same RFC-token validator used for trusted
   policy construction;
2. requires the received spelling to equal that canonical value exactly; and
3. checks the canonical value against the positive method allowlist.

Any failure raises the generic `EgressNotAllowedError` before connection-pool or
network activity.

## Primary references

- [RFC 9110 section 9.1: Methods—Overview](https://www.rfc-editor.org/rfc/rfc9110.html#section-9.1)
- [RFC 9110 section 5.6.2: Tokens](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.2)
- [CWE-444: Inconsistent Interpretation of HTTP Requests](https://cwe.mitre.org/data/definitions/444.html)
