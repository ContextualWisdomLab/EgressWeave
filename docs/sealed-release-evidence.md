# Sealed release evidence verification

## Purpose and current status

EgressWeave can verify a release-evidence directory **without executing a wheel,
source distribution, build hook, or repository script from that directory**. The
shipped `egressweave.release_evidence` module validates the exact distribution
and CycloneDX payload set, binds it to the exact repository and 40-character
protected-main commit, and emits a deterministic handoff manifest for a
separately reviewed credentialed workflow.

This verifier is a credential-free preparation control. It does not sign an
artifact, publish a release, prove provenance by itself, or authorize a pull
request to modify a signing workflow. Signed SBOM integration remains dependent
on the organization-owned reusable workflow tracked in
`ContextualWisdomLab/.github#783`; repository-level completion remains tracked
in `ContextualWisdomLab/EgressWeave#46`.

## Exact input contract

The evidence directory must be a real directory, not a symlink, and contain
exactly five regular direct-child files for one stable `X.Y.Z` version:

```text
egressweave-X.Y.Z-py3-none-any.whl
egressweave-X.Y.Z-py3-none-any.whl.cdx.json
egressweave-X.Y.Z.tar.gz
egressweave-X.Y.Z.tar.gz.cdx.json
SHA256SUMS
```

`SHA256SUMS` must be ASCII, use LF line endings, end with one newline, contain
one lowercase SHA-256 entry for each of the four payload files, and order entries
by filename. Paths, duplicates, omitted payloads, additional payloads, and
noncanonical checksum syntax fail closed.

The verifier applies a 256 MiB ceiling to each distribution, an 8 MiB ceiling to
each SBOM, and a 64 KiB ceiling to `SHA256SUMS`. These are evidence-verification
limits, not network or application response limits. Size is enforced while each
opened descriptor is consumed rather than trusted from a path-level metadata
check.

Each selected payload is opened as a descriptor-bound regular file. The verifier
compares the current path's device and inode with the opened descriptor and
rejects symlinks, non-regular descriptors, disappearing paths, or substitutions.
For `SHA256SUMS` and each SBOM, the exact parsed byte snapshot must match bounded
digests taken immediately before and after the read. The accepted checksum-file
digest is retained through semantic verification. After all CycloneDX semantics
and artifact bindings have been checked, every distribution and SBOM is hashed
again and `SHA256SUMS` is independently rehashed against its retained snapshot;
any change to any of the five accepted files prevents manifest issuance.

Each SBOM must satisfy the EgressWeave release profile:

- exact CycloneDX 1.7 JSON schema, format, specification version, and integer
  document version `1`;
- strict RFC 8259 JSON with no duplicate object names, `NaN`, or infinities;
- canonical lowercase `urn:uuid:` identity using UUID version 5, recomputed from
  the complete pre-serial SBOM semantics rather than trusted as input;
- exact root-component `bom-ref`, SHA-256, package name, version, package URL,
  and artifact-filename property bound to the paired distribution bytes.

## Operator procedure

Run the verifier in the credential-free build or verification job, after the
canonical distributions and both deterministic SBOMs have been produced and
checksummed:

```bash
PYTHONPATH=src python -m egressweave.release_evidence \
  --evidence-dir release-evidence \
  --repository ContextualWisdomLab/EgressWeave \
  --source-sha "$GITHUB_SHA" \
  --output "$RUNNER_TEMP/release-evidence-manifest.json"
```

The evidence directory should already be sealed against concurrent writes by the
build system or artifact service. The descriptor and repeated-digest checks are
a fail-closed verification boundary, not a substitute for an immutable storage
handoff or an independently supplied container digest.

The output path must remain outside the verified directory so manifest creation
cannot change the set it just accepted. Repeating the command over identical
inputs produces byte-identical JSON. The manifest records:

- format name and version;
- exact repository and source commit;
- CycloneDX version and in-toto predicate type;
- canonical artifact filename, kind, SHA-256, paired SBOM filename, SBOM
  SHA-256, and recomputed serial number for each distribution.

A later credentialed job must consume only a sealed copy of the already verified
payloads and the independently digest-bound manifest. It must recheck repository,
source commit, payload cardinality, and every digest before requesting an
attestation. It must not rebuild, resolve dependencies, import the distributions,
or execute caller-controlled source under `id-token: write`,
`attestations: write`, package-publication, release, tag, or repository-write
credentials.

## Threat model and failure behavior

The verifier addresses accidental or hostile evidence substitution between a
credential-free build and a credentialed attestation boundary. It rejects:

- stale or wrong repository/source identity;
- symlinked directories or payloads, nested paths, non-files, and extra files;
- path-to-descriptor identity changes and mutation of any accepted evidence file
  before manifest issuance;
- version disagreement between wheel and source distribution;
- missing, duplicate, malformed, unsorted, or mismatched checksums;
- oversized evidence intended to exhaust memory or runner storage;
- ambiguous JSON, downgraded CycloneDX envelopes, copied/random identifiers,
  and SBOMs bound to different distribution bytes.

Every rejection exits nonzero before a handoff manifest is written. Error text
identifies the failed evidence class but does not make the evidence trusted.
Operators must discard the complete candidate set, rebuild from the exact
protected-main head in a clean credential-free environment, and rerun all
quality, security, package, SBOM, checksum, and manifest gates. Editing a failed
manifest or checksum file in place is not a recovery procedure.

The verifier does not defend against a compromised runner kernel, a malicious
credentialed reusable workflow, or a party that can replace both the sealed
artifact container and its independently supplied digest. Those controls belong
to the organization workflow, protected environments, immutable action pins,
independent review, and offline attestation verification.

## Standalone and modular use

The verifier ships with EgressWeave and runs as
`python -m egressweave.release_evidence` without a service dependency. Its
manifest is a versioned data handoff rather than a transport or provider
contract, so naruon and other CWL systems can store or relay it without importing
EgressWeave's HTTP client. The organization-owned attestation workflow should
remain generic and accept explicit repository, source, artifact, SBOM,
predicate, and digest inputs; it must not infer trust from this
repository-specific verifier alone.

## Claims deliberately not made

A valid manifest is not a signature, vulnerability scan, license conclusion, or
proof that a dependency is benign. No SLSA Build level is claimed. Any future
claim must use the precise form `SLSA Build Lx (v1.2)` only after every normative
requirement has been independently mapped to evidence.

## References

Bray, T. (2017). *The JavaScript Object Notation (JSON) data interchange format*
(RFC 8259). Internet Engineering Task Force.
https://www.rfc-editor.org/rfc/rfc8259

Davis, K. R., Peabody, B., & Leach, P. J. (2024). *Universally unique
identifiers (UUIDs)* (RFC 9562). Internet Engineering Task Force.
https://www.rfc-editor.org/rfc/rfc9562

ECMA International, & OWASP Foundation. (2025). *CycloneDX specification 1.7
(ECMA-424).* https://cyclonedx.org/specification/overview/

GitHub. (n.d.). *Using artifact attestations to establish provenance for
builds.* GitHub Docs. Retrieved August 5, 2026, from
https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations

GitHub. (n.d.). *Using artifact attestations and reusable workflows to achieve
SLSA v1 Build Level 3.* GitHub Docs. Retrieved August 5, 2026, from
https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/increase-security-rating

The in-toto Project. (n.d.). *Attestation predicates.* GitHub. Retrieved August
5, 2026, from
https://github.com/in-toto/attestation/blob/main/spec/predicates/README.md

Supply-chain Levels for Software Artifacts Community. (2025). *SLSA
specification version 1.2.* https://slsa.dev/spec/v1.2/
