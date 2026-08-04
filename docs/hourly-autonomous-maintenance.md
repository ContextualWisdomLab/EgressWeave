# Hourly autonomous maintenance

EgressWeave uses two deliberately separate hourly workflows. Pull-request
governance stays independent from product-development model execution, and
untrusted model-controlled source never shares a job with repository write
credentials.

## Cadence

| Minute | Workflow | Responsibility |
|---:|---|---|
| `07` | `Hourly PR Maintenance` | Inspect every open pull request, dispatch bounded review-feedback repairs, re-read live reviews and checks, update eligible branches, and merge only when the central policy permits it. |
| `37` | `Hourly Autonomous Product Development` | Run only when the repository has zero open pull requests, produce one bounded buyer-visible improvement, independently reverify it, and publish it as a normal pull request. |

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
   updates, queues, or merges anything.

The central workflow resolves its co-located scheduler implementation from the
called workflow's own immutable repository and SHA. The EgressWeave workflow
does not duplicate governance logic or execute scheduler code from a mutable
branch.

## Zero-PR product-development loop

`.github/workflows/hourly-product-development.yml` uses three fresh Ubuntu 24.04
runners. The model job can only emit a bounded patch; the reverifier can execute
that patch only inside an offline least-privilege container; and the publisher
can write to GitHub but never executes modified package code.

### 1. Read-only development and patch capture

The development job has read-only GitHub permissions and checks out `main`
without persisted credentials. It exits before model use whenever any pull
request is open. It installs the trusted base toolchain, creates a root-owned
read-only baseline outside the model workspace, and then runs OpenCode 1.18.13 from the official Linux x64 release asset
only after verifying SHA-256
`8d500b20fed2d26e537e221895b1a575476571b4f0089bb29fb13eeb8eb9e937`.
The repository secret `NVIDIA_NIM_API_KEY` is exposed only to that process
through OpenCode's documented `NVIDIA_API_KEY` provider variable. The explicit
model is `nvidia/nemotron-3-super-120b-a12b`.

The model execution boundary provides:

- block-mode runner egress restricted to the reviewed package sources, GitHub,
  and `integrate.api.nvidia.com:443`;
- deny-by-default OpenCode permissions, with edits limited to the normal bounded
  source, test, documentation, README, and CHANGELOG paths;
- no model web tools, external-directory access, task delegation, skill loading,
  shell network commands, repository write token, or workflow edits;
- disabled OpenCode auto-update, remote model-list refresh, default plugins, and
  LSP downloads;
- an exact credential-disclosure scan that reports only affected paths and never
  prints the secret value;
- a maximum of ten files and 1,000 changed lines.

After model execution, only the protected baseline copy of
`scripts/ci/hourly_product_guard.py` runs on the host. It uses an alternate Git
index and NUL-safe path handling to reject deletions, renames, mode changes,
executables, links, binaries, unsafe paths, oversized files, and oversized
diffs. The job uploads only the resulting patch, diff stat, and a short-lived
model summary. The patch is authoritative; generated prose is never injected
into the pull-request review context.

### 2. Credential-free isolated reverification

A fresh runner has no secrets, no OIDC permission, and no repository-write
permission. Before applying the patch, it builds a verifier image from the
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
source. A successful job emits only the protected base SHA and SHA-256 digest
of the independently verified patch.

### 3. Credential-isolated publication

A third fresh runner checks the zero-PR condition, protected-branch SHA, patch
SHA-256, and guard result again. It applies the patch for publication but does
not install or execute the modified package or tests. Only after those checks
does it obtain a write identity, preferring an organization maintenance secret
and otherwise using the centrally operated OpenCode GitHub App OIDC exchange.

The publisher creates an `agent/hourly-product-gap-*` branch and pull request
and requests squash auto-merge. It never writes directly to `main`. Normal CI,
security scans, independent review, unresolved-thread checks, branch
protection, and the hourly PR loop remain authoritative.

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
- either `PR_REVIEW_MERGE_TOKEN`, `OPENCODE_APPROVE_TOKEN`, or a working
  organization OpenCode App OIDC exchange for a write identity that triggers
  downstream pull-request events;
- the standard Docker installation available on GitHub-hosted Ubuntu runners.

The workflow fails closed when the model credential, immutable verifier image,
container isolation, or external write identity is unavailable. It never falls
back to a repository `GITHUB_TOKEN`-authored pull request or a direct `main`
write.

## Manual operation

Both workflows support `workflow_dispatch`. Manual runs use the same checks,
concurrency, permissions, patch boundary, container isolation, and publication
gates as scheduled runs. A manual run cannot bypass the zero-open-PR condition
or any repository policy.

## Agent implementation references

Anomaly. (2026). *OpenCode CLI documentation*.
https://opencode.ai/docs/cli/

Anomaly. (2026). *OpenCode providers: NVIDIA*.
https://opencode.ai/docs/providers/

NVIDIA Corporation. (2026). *NVIDIA Nemotron 3 Super 120B A12B model card*.
https://build.nvidia.com/nvidia/nemotron-3-super-120b-a12b/modelcard
