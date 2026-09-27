# Product and Technical Gap Baseline

- Status: active-PR delivery evidence; not a protected-main or release claim
- Snapshot date: 2026-09-27 (Asia/Seoul)
- Evaluated protected-main head: `bd0339bf43cf5041e861bac86a84cb6e7e32637e`
- Active pull request: [#227](https://github.com/ContextualWisdomLab/EgressWeave/pull/227)
- Evaluated failing head: `7125d60f1a5eb0ed2e7c2cb9809f53312347b0fe`

## Exact-head RCA

Workflow run [`32660653491`](https://github.com/ContextualWisdomLab/EgressWeave/actions/runs/32660653491)
failed the test matrix on Python 3.10, 3.11, 3.12, 3.13, and 3.14. Every job
reported the same nine failures after 1,016 passing tests. The first causal
error was `runtime lock entries require exactly one SHA-256 hash` from
`scripts/ci/generate_release_sbom.py::_load_runtime_lock` while reading
`requirements-ci.txt`.

The dependency update correctly selected Pygments 2.21.0 but admitted both its
universal wheel and source-distribution hashes. EgressWeave's reviewed release
contract intentionally binds each runtime-lock entry to one artifact. PyPI
identifies `2363c69b...37d9` as the platform-independent wheel and
`610ca751...5c8c` as the source distribution. Retaining only the wheel hash
restores one dependency identity across `pip --require-hashes`, SBOM generation,
and the supported Python matrix without weakening the release validator.

## Current gap and action status

| Priority | Gap | Owner action | Completion evidence | Status |
|---|---|---|---|---|
| P0 | The active dependency head cannot produce its governed release evidence because one lock entry names two artifacts. | Bind Pygments 2.21.0 to the reviewed universal wheel hash and preserve the existing single-artifact validator. | Exact-head five-version tests, 100% statement/branch coverage, release-SBOM tests, Security/SAST/SBOM/provenance, and independent review. | Active PR; revalidation required |
| P1 | Protected main has no single continuously refreshed product-gap snapshot. | Maintain this file from protected-main source, ADR/PRD/TRD evidence, active PRs, and exact Checks after each material change. | Exact protected-head refresh after merge; active PR evidence never promoted early. | Active PR |

## Boundary and non-claims

This repair changes no egress policy, DNS, TLS, HTTP framing, transport,
authorization, or runtime error behavior. It does not claim that #227 is
merge-ready or released. Queued, skipped, stale, or predecessor Checks remain
non-passing evidence.

## Primary evidence

PyPI. (2026, August 17). *Pygments 2.21.0 release files*.
https://pypi.org/project/Pygments/2.21.0/
