# HTTP request-target authority overrides

EgressWeave validates and pins one origin, but HTTP has more than one way to
carry routing information. RFC 9112 defines several request-target forms. The
ordinary origin-form contains only a path and optional query, while the
absolute-form carries a complete URI and is used when sending a request to a
forward proxy.

HTTPX and HTTPCore expose a low-level `target` request extension that replaces
the target derived from the request URL. HTTPCore documents this extension for
absolute-form proxy requests, `CONNECT` authority-form targets, and
server-wide `OPTIONS *` requests. Passing the extension through a pinned client
would therefore create a second destination channel: an attacker could connect
to an allowlisted service that behaves as a forward proxy while asking it to
fetch an unvalidated absolute URI, including link-local or private services.
Disallowing `CONNECT` alone does not close the absolute-form `GET` or `POST`
case.

EgressWeave rejects every caller-supplied `target` extension before either the
synchronous or asynchronous request reaches HTTPCore. The transport continues
to construct the request target exclusively from the validated HTTPX URL's
`raw_path`, while restoring the validated `Host` header and TLS server name.
This is intentionally fail-closed: even a target value that appears equivalent
to the URL path is rejected so the extension cannot become an unreviewed
routing surface after a dependency upgrade.

## Primary references

- [RFC 9112 section 3.2: Request Target](https://www.rfc-editor.org/rfc/rfc9112.html#section-3.2)
- [RFC 9112 section 3.2.2: absolute-form](https://www.rfc-editor.org/rfc/rfc9112.html#section-3.2.2)
- [HTTPCore extensions: `target`](https://www.encode.io/httpcore/extensions/#target)
- [HTTPX extensions: `target`](https://www.python-httpx.org/advanced/extensions/#target)
- [OWASP SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
