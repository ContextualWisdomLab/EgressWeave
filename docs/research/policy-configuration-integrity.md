# Trusted policy configuration value integrity

## Decision

EgressWeave treats policy construction as a trusted startup boundary and stores a
canonical immutable policy value after normalization. Integer-form policy inputs
that become durable authority or resource-limit state therefore accept only an
exact built-in `int`. Non-exact integer subclasses are rejected instead of being
retained inside `EgressPolicy`.

HTTP method policy values follow the same closed-value principle. Each individual
method token entering the shared method normalizer must be an exact built-in
`str` before whitespace removal or uppercasing. A `str` subclass is therefore
rejected instead of allowing subclass-controlled `strip()` or `upper()` behavior
to participate in trusted policy construction.

The reviewed operator-configuration contract remains unchanged. ASCII decimal
strings are accepted where the corresponding integer field already supports them
and are converted to exact built-in integers before range checks, relational
checks, policy fingerprinting, DNS validation, request validation, or transport
delegation. Exact built-in integers continue to be accepted directly. For HTTP
methods, ordinary exact strings remain accepted either as iterable entries or via
the existing comma-separated `allowed_methods` string form; those exact strings
are normalized to uppercase and then checked against the RFC 9110 token grammar.
`CONNECT` remains unconditionally forbidden because it can open a tunnel to a
second destination independently of the validated URL authority.

The integer restriction applies to the shared normalization paths for allowed
ports, maximum resolved-address count, positive header-field counts, and positive
request/response byte budgets. The string restriction applies to individual HTTP
method policy values. Neither change alters configured defaults, allowed ranges,
authority pairing, DNS policy, TLS identity, proxy isolation, request/response
framing, generic request-time denial behavior, or public builder signatures.

## Why exact type matters at this boundary

Python deliberately supports subclassing immutable built-in types such as
`int` and `str`. Python's language reference permits immutable-type subclasses to
customize instance creation, and normal method dispatch on a subclass may invoke
subclass-defined behavior. A broad `isinstance(value, int)` or
`isinstance(value, str)` check is therefore a polymorphism contract, not proof
that trusted configuration contains the canonical built-in primitive expected by
a closed immutable policy representation.

EgressWeave does not need that polymorphism for policy scalar fields. Supported
customization is expressed through documented primitive values, not user-defined
numeric or string classes. Requiring `type(value) is int` on integer-form inputs
prevents a subclass object from surviving normalization and later participating
in policy hashing/equality, authority tuples, arithmetic or comparison
boundaries, or provider delegation. Requiring `type(value) is str` for individual
HTTP method entries prevents a subclass from controlling whitespace removal or
case normalization before token validation. Reviewed environment text still
reaches canonical built-in values through the explicit parsing paths described
above.

This supported-value sealing does not make EgressWeave a Python sandbox. Code
that is already executing inside the embedding process retains ordinary Python
capabilities. The boundary exists to make the documented policy value object
canonical, predictable, reviewable, and stable across standalone and modular
integrations.

## Enforcement invariants

1. Integer-form allowed ports must be exact built-in integers; reviewed ASCII
   decimal strings are converted to built-in integers.
2. Integer-form DNS candidate limits must be exact built-in integers; reviewed
   ASCII decimal strings are converted before positivity checks.
3. Shared positive field-count and byte-budget normalizers reject integer
   subclasses and preserve their existing positive-value constraints.
4. Booleans remain invalid integer configuration even though Python defines
   `bool` as an `int` subclass.
5. Every individual HTTP method policy value must be an exact built-in `str`
   before `strip()` or `upper()` is invoked.
6. The existing comma-separated `allowed_methods` configuration form remains
   supported because the public constructor splits that exact built-in string
   into ordinary built-in method strings before per-method normalization.
7. Method normalization still requires a non-empty RFC 9110 token, produces the
   canonical uppercase form, and rejects `CONNECT` unconditionally.
8. Existing decimal-string syntax, defaults, public builder signatures, and
   request-time generic denial behavior remain unchanged.
9. Invalid trusted startup configuration continues to raise actionable
   field-specific `TypeError` or `ValueError` rather than becoming an opaque
   request-time policy denial.
10. Regression tests exercise the public `EgressPolicy` constructors so these
    contracts are proven at the API boundary rather than only against internal
    helpers.

## Operator migration

Applications that supply plain integers, ASCII decimal environment values,
ordinary built-in method strings, or the existing comma-separated method string
need no change. Applications that pass custom subclasses of `int` for ports or
finite resource budgets should supply an ordinary built-in integer instead.
Applications that pass custom subclasses of `str` as individual method entries
should supply ordinary built-in strings instead. These are pre-1.0 tightenings of
ambiguous configuration shapes; they do not widen egress authority or change any
finite default.

## References — APA 7th

Fielding, R., Nottingham, M., & Reschke, J. (2022). *HTTP semantics* (RFC 9110;
STD 97). RFC Editor. https://www.rfc-editor.org/rfc/rfc9110.html

Python Software Foundation. (2026). *Data model — Python 3.14.6 documentation*.
https://docs.python.org/3.14/reference/datamodel.html
