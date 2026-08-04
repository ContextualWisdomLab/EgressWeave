# Protocol switching and proxy-only request fields

EgressWeave validates and pins one HTTP origin, but a request can still try to
change the semantics of the already-open connection. A protocol upgrade is not
a second DNS lookup, yet it can turn a validated HTTP connection into a
bidirectional channel governed by a different protocol. Proxy-only fields can
also leak credentials or introduce semantics that do not belong on EgressWeave's
direct, proxy-disabled transport.

## Standards basis

RFC 9110 defines several relevant boundaries:

- section 7.6.1 defines `Connection` as a hop-by-hop control field whose options
  apply only to the immediate connection and can nominate additional fields as
  connection-specific;
- section 7.8 defines `Upgrade`, which allows a client and server to switch the
  existing connection to another protocol after an HTTP response;
- section 11.7.2 defines `Proxy-Authorization` credentials as applying only to
  the next inbound proxy that demanded authentication; and
- section 3.3 notes that a successful `CONNECT` or protocol upgrade can cause an
  HTTP connection to become a tunnel.

Primary references:

- [RFC 9110 section 3.3: Connections, Clients, and Servers](https://www.rfc-editor.org/rfc/rfc9110.html#section-3.3)
- [RFC 9110 section 7.6.1: Connection](https://www.rfc-editor.org/rfc/rfc9110.html#section-7.6.1)
- [RFC 9110 section 7.8: Upgrade](https://www.rfc-editor.org/rfc/rfc9110.html#section-7.8)
- [RFC 9110 section 11.7.2: Proxy-Authorization](https://www.rfc-editor.org/rfc/rfc9110.html#section-11.7.2)

## EgressWeave sender invariant

EgressWeave creates a direct HTTP/1.1 connection to one validated and pinned
origin. Environment proxies are disabled, HTTP/2 is disabled, and the public
client does not expose protocol-upgrade handling. The transport therefore
rejects caller-supplied fields that attempt to control connection persistence,
initiate protocol switching, or carry proxy authentication state:

- `Connection`
- `Keep-Alive`
- `Upgrade`
- `Proxy-Authenticate`
- `Proxy-Authorization`
- `Proxy-Connection`

The rejection happens immediately before HTTPCore dispatch in both synchronous
and asynchronous transports and uses the same generic policy error as other
egress denials. Ordinary origin `Authorization` remains allowed. A single
`Transfer-Encoding: chunked` also remains supported because HTTPX emits it for
unknown-length streaming request bodies; its framing is validated separately.

This is intentionally stricter than a general-purpose HTTP client. Connection
lifetime is controlled by the client and its pool settings rather than by
untrusted per-request fields, and a caller cannot transform an approved HTTP
request into a long-lived upgraded channel.
