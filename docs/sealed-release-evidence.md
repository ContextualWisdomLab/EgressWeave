# Sealed release evidence verification

## Purpose and current status

EgressWeave verifies one release-evidence directory **without executing a wheel,
source distribution, build hook, or repository script from that directory**. The
shipped `egressweave.release_evidence` module validates the exact distribution,
CycloneDX, repository, and source-commit evidence set and emits a deterministic
handoff manifest for a separately reviewed credentialed workflow.

The verifier is a credential-free preparation control. It does not sign an
artifact, publish a release, prove that artifacts were honestly built from the
claimed source, or authorize pull-request code to modify a signing workflow.
Protected SBOM attestation and publication remain dependent on the
organization-owned reusable workflow tracked in `ContextualWisdomLab/.github#783`;
repository-level completion remains tracked in
`ContextualWisdomLab/EgressWeave#46`.

## Exact six-file input contract

The verifier computes the lexical absolute form of the supplied evidence path and
requires it to equal the strict filesystem-resolved path to a real directory.
Neither the final directory nor any ancestor component may be a symbolic link.
After this check, the verifier uses the resolved real path for every subsequent
read so retargeting a caller-supplied ancestor link cannot change the verified
root. The directory must contain exactly six regular direct-child files for one
stable `X.Y.Z` version:

```text
egressweave-X.Y.Z-py3-none-any.whl
egressweave-X.Y.Z-py3-none-any.whl.cdx.json
egressweave-X.Y.Z.tar.gz
egressweave-X.Y.Z.tar.gz.cdx.json
SOURCE_IDENTITY.json
SHA256SUMS
```

A legacy five-file set without `SOURCE_IDENTITY.json` fails closed. This is an
intentional manifest-format-v2 migration: repository and source identity can no
longer exist only as command-line or workflow assertions.

`SHA256SUMS` must be ASCII, use LF line endings, end with one newline, contain
one lowercase SHA-256 entry for each of the five non-checksum payload files, and
order entries by filename. Paths, duplicates, omitted payloads, additional
payloads, and noncanonical checksum syntax fail closed.

The verifier applies a 256 MiB ceiling to each distribution, an 8 MiB ceiling to
each SBOM, a 4 KiB ceiling to `SOURCE_IDENTITY.json`, and a 64 KiB ceiling to
`SHA256SUMS`. These are evidence-verification limits, not network or application
response limits. Size is enforced while each opened descriptor is consumed
rather than trusted from path-level metadata.

Each selected payload is opened as a descriptor-bound regular file. The verifier
compares the current path's device and inode with the opened descriptor and
rejects symlinks, non-regular descriptors, disappearing paths, or substitutions.
For `SOURCE_IDENTITY.json`, `SHA256SUMS`, and each SBOM, the exact parsed byte
snapshot must match bounded digests taken immediately before and after the read.
The source-identity and SBOM snapshots must also match the digests already
accepted from `SHA256SUMS`, so a valid alternate JSON document cannot be swapped
in only for semantic parsing and then restored before the final rehash. The
accepted checksum-file digest is retained through semantic verification. After
all identity, CycloneDX, and artifact bindings have been checked, every
non-checksum payload is hashed again and `SHA256SUMS` is independently rehashed
against its retained snapshot. Any change to any accepted file prevents manifest
issuance.

## Canonical source-identity profile

`SOURCE_IDENTITY.json` is a versioned strict-JSON payload finalized **before**
`SHA256SUMS` is generated. Its exact canonical bytes are compact, key-sorted
ASCII-safe JSON followed by one LF:

```json
{"format":"egressweave.release-source-identity","formatVersion":1,"repository":"ContextualWisdomLab/EgressWeave","sourceSha":"0123456789abcdef0123456789abcdef01234567"}
```

The verifier requires exactly four members and no others:

- `format` must equal `egressweave.release-source-identity`;
- `formatVersion` must be the JSON integer `1`, not a Boolean or string;
- `repository` must equal `ContextualWisdomLab/EgressWeave`;
- `sourceSha` must contain exactly 40 lowercase hexadecimal characters.

Duplicate member names, non-finite values, arrays, alternate whitespace,
alternate key order, omitted trailing LF, extra members, stale identities, and
caller/identity mismatches fail closed. The identity digest participates in
`SHA256SUMS`; changing only the repository or source commit therefore changes
the sealed set and the handoff manifest bytes.

This binding proves only that the reviewed evidence set contains a specific
repository/source claim. It does not prove that the artifact was built honestly
from that source. That stronger statement requires an independently reviewed,
protected build and attestation workflow with cryptographically verifiable
provenance.

## CycloneDX release profile

Each SBOM must satisfy the EgressWeave release profile:

- exact CycloneDX 1.7 JSON schema, format, specification version, and integer
  document version `1`;
- strict RFC 8259 JSON with no duplicate object names, `NaN`, or infinities;
- canonical lowercase `urn:uuid:` identity using UUID version 5, recomputed from
  complete pre-serial SBOM semantics rather than trusted as input;
- exact root-component `bom-ref`, SHA-256, package name, version, package URL,
  and artifact-filename property bound to the paired distribution bytes;
- exact parsed bytes whose SHA-256 equals the corresponding digest accepted from
  the sealed checksum set.

## Operator procedure

In the credential-free build or verification job, first create the canonical
source identity from the exact protected-main commit. Then build the canonical
distributions and deterministic SBOMs, generate sorted `SHA256SUMS` over all five
payloads, seal the evidence directory, and run:

```bash
PYTHONPATH=src python -m egressweave.release_evidence \
  --evidence-dir release-evidence \
  --repository ContextualWisdomLab/EgressWeave \
  --source-sha "$GITHUB_SHA" \
  --output "$RUNNER_TEMP/release-evidence-manifest.json"
```

Supply the real evidence-directory path rather than a symlinked workspace alias,
bind mount alias represented by a symlink, or convenience link. The CLI rejects
any path whose lexical absolute form differs from its strict filesystem-resolved
form. This makes the directory authority used for payload verification identical
to the root excluded from manifest output.

The evidence directory should already be sealed against concurrent writes by the
build system or artifact service. Descriptor and repeated-digest checks are a
fail-closed verification boundary, not a substitute for immutable storage or an
independently supplied container digest.

The output path must remain outside the verified directory so manifest creation
cannot change the set it just accepted. The CLI checks the resolved location
before evidence verification. Immediately before descriptor creation, after the
new descriptor is bound to its path, and again after durable synchronization,
the writer resolves the current output parent and rejects any redirection into
the verified directory. Before touching the output path, it also detaches one
strict RFC 8259 JSON snapshot and rejects non-object, non-finite, Python-only, or
structurally coerced values. It creates a new owner-only file through an exclusive
descriptor, refuses an existing path or final-path symlink, flushes and durably
synchronizes the bytes, and rechecks that the path still names the same regular
descriptor. It never overwrites a prior manifest.

Manifest format version 2 records:

- format name and version;
- exact repository and source commit recovered from sealed evidence;
- `SOURCE_IDENTITY.json` filename and SHA-256;
- `SHA256SUMS` filename and SHA-256;
- CycloneDX version and in-toto predicate type;
- canonical artifact filename, kind, SHA-256, paired SBOM filename, SBOM
  SHA-256, and recomputed serial number for each distribution.

After the owner-only descriptor closes, the CLI does not report success yet. It
rebuilds the complete handoff semantics from a second independent bounded pass
over the canonical evidence root, compares the strict deterministic bytes with
the pre-publication snapshot, rereads the closed output through the same
descriptor/path and size boundary, and rechecks that its parent remains outside
the verified set. Added, removed, replaced, or semantically changed evidence and
a missing, replaced, redirected, or oversized output therefore fail closed after
publication and before the success message. The failed output is never a trusted
handoff and must be discarded.

A later credentialed job must consume only a sealed copy of the already verified
payloads and the independently digest-bound manifest. It must recheck repository,
source commit, source-identity digest, checksum digest, payload cardinality, and
every payload digest before requesting an attestation. It must not rebuild,
resolve dependencies, import distributions, or execute caller-controlled source
under `id-token: write`, `attestations: write`, package-publication, release, tag,
or repository-write credentials.

## Threat model and failure behavior

The verifier addresses accidental or hostile evidence substitution between a
credential-free build and a credentialed attestation boundary. It rejects:

- missing, malformed, mixed, stale, or caller-mismatched repository/source
  identity;
- an evidence root reached through a symlinked final or ancestor path component;
- symlinked payloads, nested paths, non-files, and extra files;
- path-to-descriptor identity changes and mutation of any accepted evidence file
  before or immediately after manifest issuance;
- semantic drift on the independent post-publication evidence pass and a closed
  manifest that disappears, is replaced, grows beyond its bound, or no longer
  matches the exact pre-publication bytes;
- an alternate valid SBOM or source identity exposed only during semantic parsing
  while different bytes remain named by the accepted checksum digest;
- pre-existing, symlinked, replaced, non-private, or non-strict handoff-manifest
  output paths and payloads, including an output parent redirected into the
  verified evidence directory during verification;
- version disagreement between wheel and source distribution;
- missing, duplicate, malformed, unsorted, or mismatched checksums;
- oversized evidence intended to exhaust memory or runner storage;
- ambiguous JSON, downgraded CycloneDX envelopes, copied or random identifiers,
  and SBOMs bound to different distribution bytes.

Every rejection exits nonzero before a trusted handoff manifest is issued. A
low-level storage failure can leave a newly created but untrusted partial output;
operators must never reuse it. Operators must discard the complete candidate set
and any failed output, rebuild from the exact protected-main head in a clean
credential-free environment, choose a fresh manifest path, and rerun all quality,
security, package, SBOM, identity, checksum, and manifest gates. Editing or
overwriting a failed manifest, source identity, or checksum file in place is not
a recovery procedure.

The verifier does not defend against a compromised runner kernel, a malicious
credentialed reusable workflow, or a party that can replace both the sealed
artifact container and its independently supplied digest. Those controls belong
to the organization workflow, protected environments, immutable action pins,
independent review, and offline attestation verification.

## Standalone and modular use

The verifier ships with EgressWeave and runs as
`python -m egressweave.release_evidence` without a service dependency. Its
versioned manifest is a provider-neutral data handoff rather than a transport
contract, so naruon and other CWL systems can store or relay it without importing
EgressWeave's HTTP client. The organization-owned attestation workflow should
remain generic and accept explicit repository, source, identity, artifact, SBOM,
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
https://doi.org/10.17487/RFC8259

CWE Content Team. (2025). *CWE-59: Improper link resolution before file access
('link following').* MITRE. https://cwe.mitre.org/data/definitions/59.html

Davis, K. R., Peabody, B., & Leach, P. J. (2024). *Universally unique
identifiers (UUIDs)* (RFC 9562). Internet Engineering Task Force.
https://doi.org/10.17487/RFC9562

ECMA International, & OWASP Foundation. (2025). *CycloneDX specification 1.7
(ECMA-424).* https://cyclonedx.org/specification/overview/

GitHub. (n.d.). *Using artifact attestations to establish provenance for
builds.* GitHub Docs. Retrieved August 6, 2026, from
https://docs.github.com/en/actions/how-to/secure-your-work/use-artifact-attestations/use-artifact-attestations

GitHub. (n.d.). *Using artifact attestations and reusable workflows to achieve
SLSA v1 Build Level 3.* GitHub Docs. Retrieved August 6, 2026, from
https://docs.github.com/en/actions/how-to/secure-your-work/use-artifact-attestations/increase-security-rating

IEEE Computer Society, & The Open Group. (2018). *IEEE standard for information
technology—Portable operating system interface (POSIX®) base specifications,
Issue 7* (IEEE Std 1003.1-2017). The Open Group.
https://pubs.opengroup.org/onlinepubs/9699919799/

The in-toto Project. (n.d.). *Attestation framework specification.* GitHub.
Retrieved August 6, 2026, from
https://github.com/in-toto/attestation

Supply-chain Levels for Software Artifacts Community. (2025). *SLSA
specification version 1.2.* https://slsa.dev/spec/v1.2/
