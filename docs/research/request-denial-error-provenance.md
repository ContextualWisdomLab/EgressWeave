# Request-denial exception provenance boundary

- **Capability maturity:** ACTIVE-PR
- **Protected-main baseline:** `a7fe3a82bc5f502d417436ecc8fc0c592bffc06c`
- **Scope:** request-time HTTP method rejection only

## Security question

EgressWeave deliberately exposes one public policy-denial message:
`EgressNotAllowedError("egress URL is not allowed")`. That message is only a
complete non-disclosure boundary when caller-visible exception provenance is
also generic. Python exceptions retain `__cause__` and `__context__`, so wrapping
an untrusted parsing or normalization failure while the caught exception remains
active can disclose implementation detail even when `str(error)` is generic.

CWE-209 identifies detailed error output as a confidentiality weakness when it
reveals information useful to an unintended audience, and recommends handling
exceptions internally while exposing only minimal required detail. OWASP's Error
Handling Cheat Sheet likewise recommends generic external responses while
retaining detailed diagnostics only in a separately controlled internal channel.
EgressWeave applies the stricter payload-opaque form of that guidance: request
policy denial does not create a default diagnostic export at all.

## Contract

At the pinned transport boundary, an invalid or wrong-type request method that
causes method normalization to fail must produce a fresh generic
`EgressNotAllowedError` whose caller-visible `__cause__` and `__context__` are
both `None`. The implementation first records that normalization was denied,
leaves the active exception handler, and only then raises the public denial.
This prevents the caught `TypeError` or `ValueError` from becoming inspectable
provenance on the public exception.

This rule does **not** change trusted startup diagnostics. Invalid operator
configuration supplied to `EgressPolicy` continues to raise specific
`TypeError` or `ValueError` during policy construction. It also does not widen
method authority: the request method must still be the exact canonical token
allowed by policy, and `CONNECT` remains permanently forbidden.

## Verification boundary

The regression exercises both synchronous and asynchronous pinned transports
with an invalid HTTP method token. A test-only exact head first proved that the
protected-main implementation exposed the normalization `ValueError` through
`__cause__`; the narrow production change then made the same tests pass while
preserving all existing method-policy tests. Exact-head CI must continue to
prove full owned-production statement and branch coverage, package acceptance,
Python compatibility, SAST, and the repository's real security gates. A green
aggregate workflow does not substitute for a required security action whose
actual step was skipped.

## Privacy and operability

This control is intentionally not a masking or logging subsystem. EgressWeave
continues to avoid default export of request bodies, credentials, resolved IP
addresses, and unnecessary URL or path material. Hosts remain responsible for
application observability, retention, access control, and any approved internal
exception telemetry. A host that records internal failures must apply its own
least-privilege access and retention policy rather than relying on the public
denial object as a diagnostic carrier.

## Non-goals

- sandboxing arbitrary Python already executing inside the host process;
- changing ordinary method authorization or canonical-token rules;
- suppressing trusted configuration errors during application startup;
- adding PII masking, durable persistence, credentials, or logging authority;
- weakening dependency, review, coverage, or release gates.

## References

MITRE Corporation. (2026). *CWE-209: Generation of error message containing
sensitive information* (CWE Version 4.20).
https://cwe.mitre.org/data/definitions/209.html

OWASP Foundation. (n.d.). *Error handling cheat sheet*. OWASP Cheat Sheet
Series. Retrieved August 11, 2026, from
https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html
