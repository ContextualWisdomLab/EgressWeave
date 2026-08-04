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

For explicit TLS 1.2 compatibility, EgressWeave offers only authenticated,
ephemeral elliptic-curve Diffie-Hellman suites using AEAD ciphers. It does not
offer static RSA, finite-field DH or DHE, static ECDH, anonymous, or PSK suites.
TLS 1.3 cipher suites remain controlled by the platform's current OpenSSL
security policy.

Python's default client context is intentionally the starting point because its
verification flags, protocol defaults, and cipher policy can become more
restrictive as Python and OpenSSL evolve. RFC 10015 nevertheless imposes a
specialized TLS 1.2 requirement that a generic default cipher inventory does not
guarantee on every supported runtime: finite-field DHE and static RSA must not
be offered. The implementation therefore uses one narrow, documented
`SSLContext.set_ciphers()` call only for the explicit TLS 1.2 compatibility
mode. The Semgrep suppression is attached to that single standards-mandated call
and regression tests inspect the resulting TLS 1.2 cipher inventory.

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
representations and equality comparisons. Mutable password bytearrays are copied
to immutable bytes at construction so later caller mutation cannot change the
identity used to build a transport. A zero-argument callback remains an explicit
trusted integration point for deferred secret retrieval. Every transport owns
the fresh context that results, eliminating post-validation caller mutation as
an authority channel.

## Trust-store semantics

The default preserves EgressWeave's existing HTTPX trust behavior while
ignoring environment-controlled certificate configuration:

- `include_default_trust_store=True` loads the normal verified HTTPX roots;
- `ca_file`, `ca_path`, and `ca_data` add private trust anchors to those roots;
- `include_default_trust_store=False` uses Python's verified
  `ssl.create_default_context(cafile=..., capath=..., cadata=...)` path with only
  the explicit custom CA source and requires at least one such source.

Empty, binary path, malformed type, and ambiguous custom-only configurations
fail at startup. Trust configuration is provider-neutral and can be injected by
a standalone application, naruon adapter, or another CWL service without
embedding provider-specific certificate logic in the transport.

## Service identity binding

RFC 9525 requires a TLS client to verify the reference identity it intended to
reach against the server certificate. EgressWeave uses the same canonical,
validated hostname for the exact authority decision, TLS SNI, HTTP authority,
and Python hostname verification. Neither `TLSConfiguration` nor the request can
introduce an independent service name.

Private trust therefore changes which certification authorities are trusted; it
does not change which service identity is expected. This keeps a private CA or
mutual-TLS deployment from becoming a second authority channel that bypasses the
URL policy or DNS-pinned transport.

## Mutual TLS identity

`client_certificate_file` enables a client certificate identity. The private key
may be contained in the same PEM file or supplied through
`client_private_key_file`. `client_private_key_password` accepts the same secret
shapes supported by Python's certificate loader, including a zero-argument
callable for deferred secret retrieval. A supplied bytearray is copied to bytes
before it is retained.

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
identity; exact authority, DNS pinning, proxy isolation, request framing and
resource limits, response-resource policy, and decision evidence remain
independently enforced.

## Authoritative references

Aviram, N. (2026). *Deprecating obsolete key exchange methods in TLS 1.2 and
DTLS 1.2* (RFC 10015). RFC Editor. https://www.rfc-editor.org/rfc/rfc10015.html

Python Software Foundation. (2026). *ssl — TLS/SSL wrapper for socket objects*
(Python 3.14 documentation). https://docs.python.org/3/library/ssl.html

Saint-Andre, P., & Salz, R. (2024). *Service identity in TLS* (RFC 9525). RFC
Editor. https://www.rfc-editor.org/rfc/rfc9525.html

Salz, R., & Aviram, N. (2026). *New protocols using TLS must require TLS 1.3*
(RFC 9852; BCP 195). RFC Editor. https://www.rfc-editor.org/rfc/rfc9852.html

Sheffer, Y., Saint-Andre, P., & Fossati, T. (2022). *Recommendations for secure
use of Transport Layer Security (TLS) and Datagram Transport Layer Security
(DTLS)* (RFC 9325; BCP 195). RFC Editor.
https://www.rfc-editor.org/rfc/rfc9325.html
