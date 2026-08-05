# Deterministic SBOM attestation compatibility

## Decision

EgressWeave keeps the deterministic CycloneDX 1.7 evidence foundation in
`scripts/ci/generate_release_sbom.py` and adds a narrow compatibility adapter in
`scripts/ci/generate_attestable_release_sbom.py`.

The adapter exists because the reviewed `actions/attest` CycloneDX parser at
commit `1e69f48acb82d1966a394da916b4c1698aa569d6` accepts a document only when
`bomFormat`, `specVersion`, and `serialNumber` are all present. The foundation
intentionally omitted `serialNumber` to avoid random output. Passing the
foundation output directly to that action would therefore fail before an SBOM
attestation could be created.

## Deterministic document identity

CycloneDX 1.7 recommends an RFC 4122 UUID URN for `serialNumber`. EgressWeave
must not use a random UUID because repeated builds of the same exact source,
artifact bytes, and reviewed dependency evidence must produce byte-identical
SBOMs.

The adapter applies this fail-closed procedure:

1. Build the reviewed CycloneDX document without a serial number.
2. Serialize the complete document as sorted, compact, ASCII JSON.
3. Compute SHA-256 over those canonical bytes.
4. Append that digest to the stable EgressWeave SBOM identity URL namespace.
5. Derive an RFC 4122 UUID version 5 with the standard URL namespace.
6. Store the result as `urn:uuid:<uuid>` in `serialNumber`.

The UUID therefore identifies the complete SBOM semantics rather than only the
artifact filename. Any artifact digest, package identity, dependency version,
license, marker, relationship, property, schema, or generator change produces a
different document identity. Identical reviewed inputs produce the same UUID and
the same output bytes.

The UUID is an identity label, not a cryptographic signature. SHA-256 remains
the artifact and canonical-document binding. A signed attestation must still be
verified against the exact artifact digest, repository, protected workflow,
source commit, predicate type, and predicate bytes.

## Operator command

Build and verify the canonical distribution first, then run:

```bash
python scripts/ci/generate_attestable_release_sbom.py \
  --artifact dist/egressweave-<version>-py3-none-any.whl \
  --manifest scripts/ci/release_runtime_dependencies.json \
  --lock requirements-ci.txt \
  --output dist/egressweave-<version>-py3-none-any.whl.cdx.json
```

Repeat for the source distribution. Generate each document twice and compare the
bytes before signing. Reject the release if generation differs, the runtime lock
does not equal the reviewed manifest, the serial number is not an RFC 4122 UUID
URN, or the predicate type is not exactly `https://cyclonedx.org/bom`.

## Workflow trust boundary

This compatibility slice does **not** change `.github/workflows/release.yml`.
That workflow contains credential-separated jobs that can create an immutable
tag, publish through PyPI OIDC, and publish a GitHub Release. A pull-request
branch must not introduce or retain new branch-controlled release behavior that
receives those identities.

Protected integration remains a separate, independently reviewed action:

- generate SBOMs only from the exact verified wheel and source distribution;
- add them to release evidence and `SHA256SUMS`, not the canonical PyPI input;
- use an immutable commit-pinned attestation action;
- grant the attestation job only the permissions required by the reviewed
  action, with repository contents remaining read-only;
- verify the downloaded attestation bundle and exact predicate before public
  GitHub Release publication; and
- fail closed when protected main, the tag, artifact digest, workflow source,
  repository identity, predicate type, or predicate bytes differ.

No SLSA Build level is claimed by this adapter or by the existence of an SBOM
attestation alone.

## Recovery

If the serial number, SBOM bytes, or attestation do not verify, publish nothing.
Do not edit generated evidence, move an existing tag, or replace released bytes.
Correct the reviewed inputs through a normal pull request, rebuild from the new
exact protected-main head, and generate a new release version when any artifact
was already published.

## Authoritative references

Ecma International, & OWASP Foundation. (2025). *CycloneDX specification 1.7
(ECMA-424).* https://cyclonedx.org/specification/overview/

GitHub. (2026). *CycloneDX SBOM parsing and predicate generation* [Source code].
`actions/attest` (Commit
`1e69f48acb82d1966a394da916b4c1698aa569d6`).
https://github.com/actions/attest/blob/1e69f48acb82d1966a394da916b4c1698aa569d6/src/sbom.ts

GitHub. (n.d.). *Using artifact attestations to establish provenance for
builds.* GitHub Docs. Retrieved August 5, 2026, from
https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations

Internet Engineering Task Force. (2024). *Universally unique IDentifiers
(UUIDs)* (RFC 9562). https://doi.org/10.17487/RFC9562

in-toto Project. (n.d.). *CycloneDX predicate.* Retrieved August 5, 2026, from
https://github.com/in-toto/attestation/blob/main/spec/predicates/cyclonedx.md
