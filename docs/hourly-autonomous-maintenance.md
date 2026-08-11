# Hourly autonomous maintenance

EgressWeave uses two deliberately separate hourly workflows. Pull-request
governance stays independent from product-development model execution. The
product scheduler can produce and independently verify a bounded patch, but it
has no repository-write, ref, release, package, attestation, or publication
identity.

## Cadence

| Minute | Workflow | Responsibility |
|---:|---|---|
| `07` | `Hourly PR Maintenance` | Inspect every open pull request, dispatch bounded review-feedback repairs, re-read live reviews and checks, update eligible branches, and merge only when the central policy permits it. |
| `37` | `Hourly Autonomous Product Development` | Run only when the repository has zero open pull requests, produce one bounded buyer-visible improvement, independently reverify it, and retain a short-lived digest-bound patch handoff for external review. |

GitHub may delay scheduled runs while hosted-runner capacity is constrained.
Workflow concurrency prevents overlapping hourly runs, while repository CI
cancels superseded runs for the same pull request.

## Pull-request loop

`.github/workflows/hourly-pr-maintenance.yml` calls organization-owned reusable
workflows from `ContextualWisdomLab/.github` at an immutable commit:

1. `pr-review-fix-scheduler.yml` collects current-head review feedback and may
   dispatch the centrally controlled review autofix workflow.
2. `pr-review-merge-scheduler.yml` re-reads the live pull request, reviews,
   unresolved threads, required checks, branch state, and head SHA before it
   updates anything. This repository disables scheduler merges; an operator
   must perform the final normal protected merge after rechecking that evidence.

The central workflow resolves its co-located scheduler implementation from the
called workflow's own immutable repository and SHA. The EgressWeave product
scheduler does not repurpose or alter that inherited review-agent credential
contract.

## Zero-PR product-development loop

`.github/workflows/hourly-product-development.yml` uses two fresh Ubuntu 24.04
runners. The model job can only emit a bounded patch and does not execute
model-modified repository code. The reverifier executes that patch only inside
an offline least-privilege container and emits a short-lived handoff containing
the exact protected-main base SHA, patch SHA-256, and patch bytes.

The scheduler does not create a branch, pull request, or auto-merge request. It
does not obtain a repository-write token, exchange OIDC for a GitHub App token,
move a ref, reapply a patch under a write identity, publish a package, or create
a release.

Both zero-open-PR decisions—the initial development gate and the independent
reverification gate—use GitHub CLI pagination and sum every REST response page.
A pull request beyond the first 100 results therefore still blocks model
execution and reverification. The second gate also requires the protected-main
head to equal the exact base SHA captured before model execution.

### 1. Read-only development and patch capture

The development job has read-only GitHub permissions and checks out `main`
without persisted credentials. It exits before model use whenever any pull
request is open. It installs the trusted base toolchain, creates a root-owned
read-only baseline outside the model workspace, and then runs OpenCode 1.18.13
from the official Linux x64 release asset only after verifying SHA-256
`8d500b20fed2d26e537e221895b1a575476571b4f0089bb29fb13eeb8eb9e937`.
The repository secret `NVIDIA_NIM_API_KEY` is exposed only to that process
through OpenCode's documented `NVIDIA_API_KEY` provider variable. The explicit
model is `nvidia/nemotron-3-super-120b-a12b`.

The model execution boundary provides:

- block-mode runner egress restricted to reviewed package sources, GitHub, and
  `integrate.api.nvidia.com:443`;
- deny-by-default OpenCode permissions, with edits limited to the bounded source,
  test, documentation, README, and CHANGELOG paths;
- an isolated empty `HOME` and XDG configuration/data/cache roots, plus
  `OPENCODE_DISABLE_PROJECT_CONFIG=true`, so repository or runner OpenCode
  configuration, auto-discovered agents, commands, and plugins cannot augment
  the reviewed in-memory permission policy;
- no model web tools, external-directory access, task delegation, skill loading,
  language-server execution, shell network commands, repository write token, or
  workflow edits;
- no Ruff, pytest, compileall, Python-module, code-generation, or other
  model-modified repository execution while the model credential is present;
  only exact read-only Git diff and status commands are permitted;
- disabled OpenCode auto-update, remote model-list refresh, default plugins, and
  LSP downloads;
- an exact credential-disclosure scan that reports only affected paths and never
  prints the secret value;
- a maximum of ten files and 1,000 changed lines.

The model must place a focused regression test before its production change,
but it cannot execute either one in the credential-bearing step. Executable
validation is deliberately deferred to the fresh secret-free verifier so a
repository prompt injection cannot turn a generated test, import hook, plugin,
or language server into a credential-reading program.

After model execution, only the protected baseline copy of
`scripts/ci/hourly_product_guard.py` runs on the host. It uses an alternate Git
index and NUL-safe path handling to reject deletions, renames, mode changes,
executables, links, binaries, unsafe paths, oversized files, and oversized
diffs. The job uploads the resulting patch, diff stat, and model result only for
the next credential-free job. That first artifact is untrusted until independent
reverification succeeds.

### 2. Credential-free isolated reverification

A fresh runner has no secrets, no OIDC permission, and no repository-write
permission. Before applying the patch, it rechecks all open pull-request pages
and the exact protected-main base SHA. It then builds a verifier image from the
protected branch and installs the trusted dependency and test toolchain. The
Python base image is resolved to an immutable repository digest, and the built
verifier is addressed by its immutable image ID.

The trusted guard validates patch metadata before `git apply`, revalidates the
materialized diff, and seals the patch identity in root-owned read-only files.
Modified source and tests then execute only in a container configured with:

- no network or IPC namespace sharing;
- all Linux capabilities dropped and `no-new-privileges` enabled;
- a read-only root filesystem and non-root UID/GID;
- bounded CPU, memory, process count, and writable tmpfs storage;
- a read-only source mount and no Docker socket, secrets, or host write mount.

Inside that boundary, Ruff, pytest, and compileall run against the patched
source. The job rehashes the sealed patch and validates the 40-character base
SHA before uploading exactly three owner-readable files:

```text
egressweave.patch
base-sha
patch-sha256
```

The artifact name includes the workflow run and attempt, and retention is three
days. Successful reverification proves only that this exact patch passed the
configured checks against this exact base in the isolated job. It is not a pull
request, approval, merge authorization, provenance statement, or release.

### 3. External promotion boundary

No repository-local product-development job promotes the verified handoff. A
future external credential-separated promotion mechanism may consume it only
after independent review of that mechanism and its immutable source. Before any
repository write, that mechanism must independently acquire the exact artifact,
verify the base SHA and patch SHA-256, reconstruct and verify the exact tree,
recheck the live protected-main head and complete pull-request state, and obtain
all required independent approvals and security gates.

No such promotion mechanism is claimed by this repository. When it is absent,
the verified artifact expires without publication. Operators must not manually
reinterpret a successful reverification job as permission to push, open a pull
request, enable auto-merge, or bypass branch protection.

## Model change boundary

The autonomous maintainer may modify only:

- `src/egressweave/**`
- `tests/**`
- `docs/**`
- `README.md`
- `CHANGELOG.md`

It may not modify workflows, `scripts/**`, agent instructions, licenses,
`pyproject.toml`, dependencies, build configuration, generated files, caches,
or lockfiles. It also may not alter repository history; delete or rename files;
change file modes; create executables, hard links, symlinks, or binaries; touch
more than ten files; exceed 512 KiB per file or 2 MiB overall; or produce a diff
larger than 1,000 changed lines.

## Required configuration

The scheduled product-development workflow requires:

- `NVIDIA_NIM_API_KEY`, mapped only to OpenCode's `NVIDIA_API_KEY`
  environment variable for the NVIDIA NIM endpoint;
- the standard Docker installation available on GitHub-hosted Ubuntu runners.

The workflow fails closed when the model credential, protected base identity,
immutable verifier image, container isolation, or patch identity is unavailable.
It has no fallback repository-write identity and does not reuse review-agent,
release, package, attestation, or ref credentials.

## Manual operation

Both workflows support `workflow_dispatch`. Manual product-development runs use
the same read-only permissions, exact-base checks, patch boundary, container
isolation, full REST pagination, and non-publication boundary as scheduled runs.
A manual run cannot bypass the zero-open-PR condition or turn the verified
handoff into a repository write.

## Agent implementation references

Anomaly. (2026). *OpenCode CLI documentation*.
https://opencode.ai/docs/cli/

Anomaly. (2026). *OpenCode providers: NVIDIA*.
https://opencode.ai/docs/providers/

NVIDIA Corporation. (2026). *NVIDIA Nemotron 3 Super 120B A12B model card*.
https://build.nvidia.com/nvidia/nemotron-3-super-120b-a12b/modelcard
