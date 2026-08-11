# Trusted policy configuration value integrity

## Decision

EgressWeave treats policy construction as a trusted startup boundary and stores a
canonical immutable policy value after normalization. Integer-form policy inputs
that become durable authority or resource-limit state therefore accept only an
exact built-in `int`. Non-exact integer subclasses are rejected instead of being
retained inside `EgressPolicy`.

The reviewed environment-configuration contract remains unchanged: ASCII decimal
strings are accepted where the corresponding public field already supports them
and are converted to exact built-in integers before range checks, relational
checks, policy fingerprinting, DNS validation, request validation, or transport
delegation. Exact built-in integers continue to be accepted directly.

This restriction applies to the shared integer normalization paths for allowed
ports, maximum resolved-address count, positive header-field counts, and positive
request/response byte budgets. It does not change configured defaults, allowed
ranges, authority pairing, DNS policy, TLS identity, proxy isolation, HTTP method
policy, request/response framing, or the generic request-time denial boundary.

HTTP method policy values are sealed at the same trusted startup boundary. Each
method value must be an exact built-in `str` before trimming, uppercase
canonicalization, or RFC 9110 token validation can invoke string behavior.
Supported comma-separated operator syntax remains available only when the outer
configuration value itself is an exact built-in `str`; non-exact string
subclasses are rejected before `split()` can run. Runtime method authorization
uses the same exact-string boundary and returns the existing generic denial for
unsupported caller values.

This method-value restriction preserves the documented default and deny-all sets,
ordinary exact strings, comma-separated ergonomics, uppercase canonicalization,
RFC 9110 token validation, and unconditional `CONNECT` denial. It does not make
EgressWeave a Python sandbox: arbitrary trusted Python already executing in the
embedding process retains ordinary Python capabilities.

## Why exact type matters at this boundary

Python deliberately supports subclassing immutable built-in types such as `int`,
and `isinstance(value, int)` is true for instances of subclasses. Python's data
model also permits subclasses of immutable built-ins to customize instance
creation. A broad `isinstance` check is therefore a polymorphism contract, not
proof that the stored object is the canonical built-in integer value expected by
a closed immutable policy representation.

EgressWeave does not need that polymorphism for policy scalar fields. Supported
customization is expressed through documented values, not user-defined numeric
classes. Requiring `type(value) is int` on integer-form inputs prevents a subclass
object from surviving normalization and later participating in policy hashing or
equality, authority tuples, arithmetic or comparison boundaries, or provider
delegation. Environment text still reaches the same canonical state through
explicit decimal conversion.

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
5. Existing decimal-string syntax, defaults, public builder signatures, and
   request-time generic denial behavior remain unchanged.
6. Invalid trusted startup configuration continues to raise actionable
   field-specific `TypeError` or `ValueError` rather than becoming an opaque
   request-time policy denial.
7. Regression tests exercise the public `EgressPolicy` constructors so the
   contract is proven at the API boundary rather than only against internal
   helpers.
8. HTTP method entries and supported comma-separated method configuration must
   be exact built-in strings before any subclass-controllable normalization or
   splitting operation.
9. Runtime HTTP method authorization rejects non-exact string subclasses without
   invoking their normalization methods.

## Operator migration

Applications that supply plain integers or ASCII decimal environment values need
no change. Applications that pass custom subclasses of `int` for ports or finite
resource budgets should materialize an exact built-in integer before policy
construction. This is a pre-1.0 tightening of an ambiguous configuration shape;
it does not widen egress authority or change any finite default.

Applications that supply ordinary method strings or the existing comma-separated
method syntax also need no change. Integrations that pass subclasses of `str` for
method configuration should materialize exact built-in strings before policy
construction. This is likewise a supported-value tightening, not an expansion of
HTTP authority.

## Reference — APA 7th

Python Software Foundation. (2026). *Data model — Python 3.14.6 documentation*.
https://docs.python.org/3.14/reference/datamodel.html
