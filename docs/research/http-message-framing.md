# HTTP/1.1 request framing and request smuggling

EgressWeave validates raw outbound fields immediately before HTTPCore dispatch.
That boundary also needs to enforce one unambiguous request-body framing signal:
otherwise a caller can construct byte headers that different HTTP recipients
interpret as different message boundaries.

## Standards basis

RFC 9112 defines HTTP/1.1 message framing in sections 6.1 through 6.3:

- a sender **must not** send `Content-Length` in a message that also contains
  `Transfer-Encoding`;
- a valid `Content-Length` is a decimal number of octets;
- a request whose final transfer coding is not `chunked` cannot be framed
  reliably; and
- a message containing both framing fields can indicate request smuggling and
  ought to be handled as an error.

RFC 9112 section 11.2 describes request smuggling as an attack that exploits
parsing differences among multiple recipients to hide additional requests.
CWE-444 likewise calls out duplicate `Content-Length`, duplicate
`Transfer-Encoding`, and mixed `Transfer-Encoding`/`Content-Length` fields as
common interpretation-conflict patterns.

Primary references:

- [RFC 9112 section 6.1: Transfer-Encoding](https://www.rfc-editor.org/rfc/rfc9112.html#section-6.1)
- [RFC 9112 section 6.2: Content-Length](https://www.rfc-editor.org/rfc/rfc9112.html#section-6.2)
- [RFC 9112 section 6.3: Message Body Length](https://www.rfc-editor.org/rfc/rfc9112.html#section-6.3)
- [RFC 9112 section 11.2: Request Smuggling](https://www.rfc-editor.org/rfc/rfc9112.html#section-11.2)
- [CWE-444: Inconsistent Interpretation of HTTP Requests](https://cwe.mitre.org/data/definitions/444.html)

## EgressWeave sender invariant

EgressWeave is a sender, not a tolerant recipient. It therefore uses a stricter
canonical contract than the recipient recovery rules permit:

1. at most one `Content-Length` field;
2. at most one `Transfer-Encoding` field;
3. never both fields in the same request;
4. `Content-Length` must be a non-empty ASCII decimal value; and
5. `Transfer-Encoding` must be the single `chunked` coding emitted by HTTPX for
   an unknown-size streaming body.

Duplicate lengths are rejected even when numerically identical, and comma-joined
length lists are rejected rather than normalized. Unsupported transfer codings
are also rejected because the pinned transport does not apply those coding
transformations itself. These constraints preserve ordinary fixed-size and
HTTPX streaming requests while removing parser-dependent framing choices before
any persistent connection can be used.
