# HTTPCore request-extension capability boundary

## Purpose

EgressWeave treats low-level HTTPCore request extensions as security-relevant
capabilities rather than opaque metadata. The pinned transports therefore use a
positive allowlist: only the reviewed `timeout` metadata and the validated
`sni_hostname` identity channel may reach HTTPCore. Every other request
extension must fail closed with the same generic `EgressNotAllowedError` used for
other indeterminate egress decisions.

This boundary is intentionally narrower than HTTPCore's general extension API.
EgressWeave is an outbound HTTP policy library, not a generic escape hatch to
HTTPCore internals.

## Architecture contract

The request path applies the extension policy before connection-pool dispatch:

```text
HTTPX request extensions
        |
        v
copy caller mapping behind generic-denial boundary
        |
        v
positive key allowlist
  |                 |
  | allow           | reject
  v                 v
`timeout`        `target`
`sni_hostname`   `trace`
                 unknown future extension
  |
  v
validate SNI against reviewed hostname
        |
        v
cap connect/read/write/pool timeouts
        |
        v
HTTPCore request
```

The mapping is detached before inspection. Ordinary exceptions raised by a
caller-controlled `Mapping` while enumerating or reading extension entries are
normalized to the generic denial instead of crossing the policy boundary.
Interpreter/process control-flow exceptions are not deliberately converted into
policy errors.

## Why `target` is denied

HTTPCore documents `target` as an override for the request target. It can be
used by proxy-style integrations and therefore creates a request-routing channel
that is independent of the normalized URL authority EgressWeave validated.
EgressWeave already owns request-target construction and size/framing controls,
so caller-supplied `target` is not compatible with the pinned-authority model.

## Why `trace` is denied

HTTPCore documents `trace` as a callback invoked for internal request,
connection, and TLS lifecycle events. The documented completion events include
operation return values. Connection completion can therefore expose a
`NetworkStream`-class transport object to caller code.

That object is a broader capability than EgressWeave's reviewed HTTP surface.
A caller holding a raw network stream could perform direct transport operations
outside EgressWeave's HTTP method, request-target, field/framing, request-body,
and response-body policy controls. For that reason `trace` is rejected before
HTTPCore can invoke the callback.

This does **not** claim that EgressWeave is a Python sandbox. Arbitrary trusted
or compromised in-process code remains outside the library's threat model. The
control prevents an ordinary low-level request extension from becoming an
advertised bypass path through the supported EgressWeave client interface.

## Why unknown extensions are denied

A denylist would become stale whenever HTTPCore adds a new extension. Because an
extension may carry routing, callback, transport, or other capability semantics,
unknown keys have no reviewed security meaning. EgressWeave therefore forwards
only the two explicitly modeled channels and requires a future security review,
regression tests, documentation, and release note before widening the allowlist.

## Allowed channels

### `sni_hostname`

A caller may supply only an exact built-in `bytes` value containing ASCII or an
exact built-in `str` hostname when it canonicalizes to the already validated
hostname. EgressWeave then overwrites the outbound extension with that validated
hostname. Alternate TLS identity is rejected.
Subclasses of `bytes` and `str` are rejected before HTTPCore dispatch with the
same generic `EgressNotAllowedError`.

### `timeout`

The timeout mapping is not trusted as supplied. EgressWeave accepts only the
reviewed `connect`, `read`, `write`, and `pool` keys; missing or disabled values
receive finite policy maxima, stricter finite non-negative values are preserved,
and larger values are capped. Malformed metadata fails closed.

## Compatibility impact

This is an intentional pre-1.0 secure-default tightening. Integrations that
previously attached HTTPCore `trace`, `target`, or private/custom request
extensions through an EgressWeave-managed client must remove those extensions or
use a separately reviewed transport outside EgressWeave. Observability should be
implemented at the host/application layer through data-minimized metrics and
traces rather than by exposing raw HTTPCore transport callbacks through the
security client.

## Verification expectations

Changes to this boundary require all of the following:

- a fail-first regression for any newly accepted or rejected extension;
- synchronous and asynchronous transport parity because both use the same
  request-safety helper;
- hostile mapping tests that prove ordinary caller-controlled exceptions do not
  leak through denial;
- exact 100% production statement and branch coverage;
- full package acceptance, SAST, security/supply-chain gates, and current-head
  review before merge;
- an explicit changelog entry when compatibility or security behavior changes.

## References

Encode OSS Ltd. (n.d.). *Extensions*. HTTPCore. Retrieved August 10, 2026, from
https://www.encode.io/httpcore/extensions/

Fielding, R. T., Nottingham, M., & Reschke, J. (2022). *HTTP semantics*
(RFC 9110). RFC Editor. https://doi.org/10.17487/RFC9110
