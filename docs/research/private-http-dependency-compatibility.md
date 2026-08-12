# Private HTTPX/HTTPCore compatibility boundary

EgressWeave implements its DNS-pinned synchronous and asynchronous transports on
reviewed private HTTPX and HTTPCore interfaces. Private interfaces can change
without a public compatibility guarantee, so package metadata must not advertise
runtime combinations that EgressWeave has not actually executed through its
security and packaging gates.

## Current supported pair

The current package contract is deliberately narrow:

- `httpx==0.28.1`
- `httpcore==1.0.9`

The same pair is present in the hash-locked CI environment. The supported
Python matrix executes the full EgressWeave suite against those identities, and
wheel/source-distribution acceptance smoke-tests the installed package outside
the source tree.

This is a compatibility boundary, not a dependency freshness claim. A newer
HTTPX or HTTPCore release is unsupported until its private surface and behavior
have been reviewed and the repository proves the candidate pair on an exact
current head. EgressWeave must not silently widen the metadata first and rely on
ordinary application tests to discover a transport-security regression later.

## Private surface under review

The compatibility review includes at least the private HTTPX transport helpers
used to map HTTPCore exceptions and adapt response streams, plus the HTTPCore
network backend, connection-pool, request, URL, and stream lifecycle exercised
by both pinned transports. The acceptance question is behavioral: exact
authority binding, DNS pinning and per-connect revalidation, TLS identity,
request/response resource limits, generic denial behavior, and deterministic
cleanup must remain intact.

An import succeeding is not sufficient compatibility evidence. Constructor
signatures, request-extension handling, stream ownership, cleanup behavior, and
exception mapping can change while the imported names still exist.

## Why exact pins are currently feasible

Exact pins trade resolver flexibility for a falsifiable security promise. This
can conflict with a host application that requires a different HTTPX or HTTPCore
version, so EgressWeave must not present the choice as cost-free. The current
trade-off is accepted because the package directly depends on private transport
interfaces and presently has executable evidence for only one dependency pair.
A host with an incompatible requirement should fail dependency resolution rather
than install an unproved private-API combination.

The long-term preferred direction is to reduce or isolate private coupling and,
when more than one dependency pair is intentionally supported, execute an
explicit compatibility matrix covering every advertised boundary. A version
range without corresponding executable profiles would recreate the assurance
gap this contract removes.

## Dependency upgrade procedure

A dependency change is a security-relevant compatibility change. Maintainers
must perform the following before changing the advertised pair:

1. select an explicit candidate HTTPX/HTTPCore pair and inspect the private
   interfaces used by both pinned transports;
2. record the observed failing contract and its exact result before changing
   `pyproject.toml`, any hash-locked requirements file, or production transport
   code;
3. add or update test-first compatibility evidence for changed shapes or
   behavior;
4. run the complete supported Python matrix, including Python 3.14 when
   supported, exact 100% owned-production statement/branch coverage, Ruff,
   compile checks, product guard, wheel/sdist verification, and installed-wheel
   smoke testing against the candidate pair;
5. exercise exact authority, DNS pinning/revalidation, TLS identity,
   request/response bounds, timeouts, pool limits, denial provenance, and stream
   cleanup for synchronous and asynchronous paths;
6. regenerate the hash-locked CI dependency identities and hashes only after the
   candidate behavior is accepted;
7. update package metadata to exactly the dependency identities actually proven,
   or widen it only when an explicit compatibility matrix covers every advertised
   boundary; and
8. require exact-current-head SAST, dependency review, remaining security gates,
   actionable-review closure, and repository governance before merge or release.

A future adapter or capability check may improve startup diagnostics for a
corrupted or manually overridden environment, but feature detection alone is not
proof that an alternate private surface preserves security behavior.

## Scope

This contract does not change EgressWeave's provider-neutral product boundary,
introduce runtime dependency discovery, download a compatibility registry, or
permit a generic-client fallback. Unsupported dependency state must fail before
an EgressWeave release claims compatibility with it.
