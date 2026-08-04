# Immutable enterprise TLS and mutual-TLS configuration

## Decision

EgressWeave exposes an immutable `TLSConfiguration` value object rather than
accepting a caller-owned `ssl.SSLContext`. Each synchronous or asynchronous
pinned transport creates one fresh verified context from the value object when
the connection pool is constructed.

The secure default is TLS 1.3. TLS 1.2 is available only as an explicit
compatibility floor for an existing integration. TLS 1.0, TLS 1.1, sentinel
minimum/maximum values, and arbitrary integer or text spellings fail during
configuration construction. Certificate verification and hostname verification
cannot be disabled.

For explicit TLS 1.2 compatibility, EgressWeave offers only ephemeral elliptic-
curve Diffie-Hellman suites using AEAD ciphers. It does not offer static RSA,
finite-field DHE, or static ECDH key exchange. TLS 1.3 cipher suites remain
controlled by the platform's current OpenSSL security policy.

## Why the context is created internally

`ssl.SSLContext` is mutable. A context that was checked by a policy layer can be
changed later by another component, including changes to verification mode,
hostname checking, trust anchors, protocol bounds, or client identity. Accepting
that mutable object would make the transport's security properties depend on
external object lifetime and mutation order.

`TLSConfiguration` instead stores declarative inputs in a frozen value object.
Path-like values are normalized to deterministic text without expanding or
resolving them, and filesystem or certificate parsing is deferred to context
construction. Secret-bearing client-key passwords are excluded from
representations and equality comparisons. Every transport owns the fresh context
that results, eliminating post-validation caller mutation as an authority
channel.

## Trust-store semantics

The default preserves EgressWeave's existing HTTPX trust behavior while
ignoring environment-controlled certificate configuration:

- `include_default_trust_store=True` loads the normal HTTPX/certifi roots;
- `ca_file`, `ca_path`, and `ca_data` add private trust anchors to those roots;
- `include_default_trust_store=False` creates an isolated trust store and
  requires at least one explicit custom CA source.

Empty, binary path, malformed type, and ambiguous custom-only configurations
fail at startup. Trust configuration is provider-neutral and can be injected by
a standalone application, naruon adapter, or another CWL service without
embedding provider-specific certificate logic in the transport.

## Mutual TLS identity

`client_certificate_file` enables a client certificate identity. The private key
may be contained in the same PEM file or supplied through
`client_private_key_file`. `client_private_key_password` accepts the same secret
shapes supported by Python's certificate loader, including a zero-argument
callable for deferred secret retrieval.

A private key or password without a certificate is rejected before filesystem
access. Certificate and key loading errors remain startup/operator errors rather
than being converted into generic runtime policy denials, because they describe
trusted deployment configuration that must be corrected before service.
Request-time destination or policy failures continue to use the generic
non-leaking `EgressNotAllowedError` boundary.

## Compatibility and migration

Existing callers that omit `tls_configuration` retain the current verified
HTTPX context and package behavior. New integrations should use the TLS 1.3
default. An existing endpoint that cannot yet negotiate TLS 1.3 can opt into
`minimum_version=ssl.TLSVersion.TLSv1_2`; this is an explicit compatibility
exception that should be inventoried and removed after the peer is upgraded.

The configuration is threaded through both public builders and both
already-validated pinned-client builders. It changes only TLS trust and client
identity; exact authority, DNS pinning, proxy isolation, request safety, and
response-resource policy remain independently enforced.

## Authoritative references

Aviram, N. (2026). *Deprecating obsolete key exchange methods in TLS 1.2 and
DTLS 1.2* (RFC 10015). RFC Editor. https://www.rfc-editor.org/rfc/rfc10015.html

Python Software Foundation. (2026). *ssl — TLS/SSL wrapper for socket objects*
(Python 3 documentation). https://docs.python.org/3/library/ssl.html

Salz, R., & Aviram, N. (2026). *New protocols using TLS must require TLS 1.3*
(RFC 9852; BCP 195). RFC Editor. https://www.rfc-editor.org/rfc/rfc9852.html

Sheffer, Y., Saint-Andre, P., & Fossati, T. (2022). *Recommendations for secure
use of Transport Layer Security (TLS) and Datagram Transport Layer Security
(DTLS)* (RFC 9325; BCP 195). RFC Editor.
https://www.rfc-editor.org/rfc/rfc9325.html
