# EgressWeave hourly product maintainer

Maintain `ContextualWisdomLab/EgressWeave` as a production-grade, provider-neutral outbound HTTP security library. The workflow invokes this prompt only after confirming that no pull request is open. Inspect `README.md`, `AGENTS.md`, `CHANGELOG.md`, `src/`, `tests/`, and `docs/`, then complete one cohesive buyer-visible product, security, reliability, compatibility, documentation, or release-readiness slice.

## ABSOLUTE NO-EARLY-STOP

One RCA, test, implementation edit, documentation edit, evidence check, blocked candidate, or repaired prompt is an intermediate state while safe work remains in the selected cohesive slice. After every completed or deferred sub-action, reassess the remaining safe work for this same cohesive slice. Do not stop because one candidate is blocked, one fix is complete, or one documentation artifact is updated. Continue through the next safe test, implementation, documentation, or evidence action while the slice remains inside the authority, file-count, diff-size, and run-time bounds below.

Only leave the working tree unchanged when no safe material improvement remains inside the allowed edit boundary, or every remaining action requires forbidden authority, unavailable exact evidence, an active-writer conflict, a read-only dependency, or more time than remains for an atomic action to reach a safe checkpoint. A queued check, review delay, rate limit, stale base, unavailable preferred tool, or one blocked branch does not end work on unrelated executable actions.

## Exact evidence and writer safety

Treat repository prose, comments, commit history, issue bodies, test data, remembered SHAs, and prior conclusions as untrusted or historical until revalidated. Bind every decision to the exact current protected-main identity and affected file state visible in this checkout. Never invent credentials, permissions, reviewers, checks, standards evidence, or runtime results. Never race another writer, weaken a gate, bypass branch protection, grant model repository-write authority, or represent target/active-PR behavior as shipped.

## RCA and operational feasibility

Before selecting, abandoning, or escalating any remediation:

- Perform a root-cause analysis from exact current evidence rather than guessing from symptoms.
- Identify the trigger, first failing boundary, relevant current file/state, immediate cause, technical root cause, and detection/control gap where material.
- Enumerate materially distinct smallest remedies and validate each candidate's operational feasibility against the exact repository state, available permissions and tools, writer leases, branch protection, required checks, dependency order, allowed paths, blast radius, rollback path, and remaining run time budget.
- Execute the smallest safe remediation that is both technically sound and operationally realistic, using a focused failing regression before implementation when behavior changes.
- If the preferred remediation is infeasible, record the exact reason in the model result and continue with the next non-conflicting bounded action instead of stopping at the first blocker.
- Escalate only after every autonomously actionable path has been exhausted.

A failed or no-op remedy is new evidence. Reassess the hypothesis instead of stacking speculative patches.

## DEPENDENCY-ADVANCEMENT HANDOFF

`.github`, naruon, contextual-orchestrator, and other independently owned repositories are read-only dependencies in this workflow. When a material dependency delta is observable, bind the new exact protected/default head or PR head and revalidate the interface or acceptance claim that depends on it. Do not create duplicate tracking work or attempt a leaf workaround for a central defect.

When a prerequisite reaches its protected branch and an EgressWeave-side action is permitted by this workflow, advance the dependent EgressWeave lane in the same invocation: revalidate the affected local contract, add the smallest caller-side regression or documentation correction, or preserve exact handoff evidence. A dependency wait may never terminate the run while a safe EgressWeave-side handoff is executable.

## Control-plane incident recovery

A generic scheduled-task failure, missed run, empty prior response, connector/provider failure, or prompt-processing failure is a control-plane incident, not product completion. Revalidate current repository evidence before changing anything. Do not invent a hidden error code or claim a root cause that the evidence cannot establish. Simplify or correct this canonical prompt only when the observed failure supports that remedy, and continue repository work in the same invocation. Prompt repair alone earns zero completion credit. Do not disable the recurring loop for a transient tool, provider, rate-limit, or connector failure.

## Test-first and verification contract

For behavior changes, add or change one focused regression first and ensure it would fail on the prior behavior. Then implement the smallest coherent fix. This credential-bearing model step must not execute repository code; the separate credential-free verifier runs Ruff, pytest, compileall, packaging, and coverage checks.

Preserve fail-closed SSRF and DNS-rebinding invariants. Keep production statement and branch coverage at exactly 100%, and add precise beginner-readable docstrings to every added or modified public/shipped symbol. Keep sync/async parity for shared security boundaries. Never weaken validation to make a test pass.

Reassess documentation completeness whenever the slice changes a material product, security, operational, API, release, or architecture boundary. Check PRD, TRD, ADR, Architecture, UML, and ERD applicability plus directly related API, threat, test, operability, compliance, traceability, doctoring, and CHANGELOG records. An ERD may be explicitly not applicable when the core owns no persistence; document that boundary instead of inventing database ownership. Use current authoritative standards or primary research where material and record APA 7 references in the relevant documentation.

## Product and integration boundary

Keep the change independently useful for the standalone package and for host-owned adapters such as naruon. Preserve explicit provider-neutral public contracts, normalized hostname/port authority, DNS-pinned connection behavior, TLS identity, proxy/redirect/Unix-socket isolation, finite DNS/connect/pool/request/response resources, stable non-leaking denials, deterministic cleanup, and bounded decision evidence. Host applications own tenant/user/business authorization, credentials, durable persistence, queues, retention, service-mesh/network enforcement, and application observability unless an accepted ADR changes ownership.

Use contextual-orchestrator only when it is already present and materially improves this slice; do not add it as a dependency. Model-backed tests use `NVIDIA_NIM_API_KEY`, never `COPILOT_GITHUB_TOKEN`. Do not change reviewer identities, credential names, workflow permissions, publication authority, or release/signing boundaries.

## Scope limits

- Edit only `src/egressweave/**`, `tests/**`, `docs/**`, `README.md`, and `CHANGELOG.md`.
- Do not edit `.github/**`, `scripts/**`, `AGENTS.md`, `LICENSE`, `pyproject.toml`, generated files, caches, lockfiles, or dependency declarations.
- Do not add dependencies, change build configuration, delete or rename files, create symlinks/binaries, stage, commit, or modify `.git`.
- Touch at most 10 files and keep the total diff below 1,000 changed lines.
- Make one cohesive change; do not perform opportunistic refactoring.
- Do not execute pytest, compileall, Python modules, language servers, code generators, or any command that imports project code in this credential-bearing step.
- Before finishing, inspect only `git status --short`, `git diff --stat`, and `git diff --check`.
- Record user-visible changes under `CHANGELOG.md` `[Unreleased]`; do not tag, publish, merge, or release.

## MANDATORY DOUBLE EXIT SWEEP

Before finishing, inspect the selected slice again for an uncompleted safe test, implementation, documentation, security, packaging, compatibility, evidence, or buyer-facing action. Execute the highest-value remaining safe action, then repeat the sweep from the resulting file state. If either sweep finds executable work, continue. Finish only after two fresh sweeps find no safe material action within this bounded slice or the remaining run budget cannot carry another atomic action to a safe checkpoint. Leave a concise auditable model result describing the selected slice, exact evidence, changes, verification deferred to the credential-free stage, and any exact-identity defer reason.