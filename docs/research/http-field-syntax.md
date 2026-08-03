# HTTP field syntax and authority integrity

EgressWeave receives HTTPX request headers as raw byte pairs at the transport
boundary. That representation is useful for exact protocol handling, but it can
also carry malformed field names or values that different HTTP parsers interpret
differently. A security transport must not delegate ambiguous syntax to a later
parser and assume every dependency version will reject it identically.

RFC 9110 defines a field name as an HTTP `token`; whitespace, colons, control
characters, and other separators are not part of that grammar. Field values may
contain visible data and normalized internal whitespace, but carriage return,
line feed, NUL, DEL, other control octets, and leading or trailing whitespace do
not form a normalized field value. RFC 9112 specifically requires rejection of
whitespace between a field name and its colon because inconsistent handling has
caused request-routing and request-smuggling vulnerabilities.

The `Host` field is additionally authority-sensitive. HTTP/1.1 recipients use it
to route a request, and duplicate or malformed host spellings can disagree with
the URL authority already validated and DNS-pinned by EgressWeave.

EgressWeave therefore validates every outbound raw field name and value before
either connection pool sees the request. Invalid syntax fails with the same
generic `EgressNotAllowedError` used for other policy violations. Every
caller-supplied case-insensitive `Host` field is removed and exactly one field
containing the validated authority is emitted. This keeps routing identity
consistent across the URL, TCP destination, TLS server name, and HTTP message.

## Primary references

- [RFC 9110 section 5.1: Field Names](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.1)
- [RFC 9110 section 5.5: Field Values](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.5)
- [RFC 9110 section 5.6.2: Tokens](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.2)
- [RFC 9112 section 5.1: Field Line Parsing](https://www.rfc-editor.org/rfc/rfc9112.html#section-5.1)
- [RFC 9112 section 7.2: Host and :authority](https://www.rfc-editor.org/rfc/rfc9112.html#section-7.2)
