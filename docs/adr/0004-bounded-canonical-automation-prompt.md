# ADR 0004: Bounded canonical automation prompt

Status: **Proposed**

Date: 2026-08-10

## Context

The repository-local hourly product-development workflow historically embedded its entire OpenCode maintainer policy inside a YAML heredoc. That made one file own workflow syntax, shell quoting, model configuration, and a growing policy document at the same time. A prior malformed `printf` escape already demonstrated that physical newline damage inside this workflow can prevent GitHub from creating any job.

The external scheduled task has also returned repeated generic failure messages without an observable error code or repository mutation. Repository evidence cannot establish whether those failures came from prompt size, scheduler serialization, a connector, a provider, a permission boundary, or another control-plane component. The architecture therefore must not claim a hidden root cause that cannot be inspected.

The durable automation semantics remain governed by [ADR 0003](0003-work-conserving-automation-and-dependency-handoff.md). This ADR narrows one implementation decision: how the repository-local model prompt is stored, bounded, loaded, and recovered after a generic control-plane failure.

## Decision

### 1. One canonical prompt source

The repository-local OpenCode maintainer policy SHALL be stored once at:

```text
.github/prompts/hourly-product-maintainer.md
```

The GitHub Actions workflow SHALL load that file into a private runner path before model execution. It SHALL NOT duplicate the full policy in an inline YAML heredoc. The canonical file is repository-owned policy input, not model-editable output; the OpenCode edit allowlist continues to deny `.github/**`.

### 2. Explicit prompt-size budget

The canonical prompt SHALL be a regular, non-symbolic-link file no larger than **12 KiB**. The workflow SHALL fail before model execution if the file is missing, is a symbolic link, has an invalid byte count, or exceeds that limit.

The 12 KiB value is an internal engineering budget chosen to keep the model handoff compact and reviewable. It is not evidence of an external scheduler limit and must not be represented as the confirmed root cause of any generic scheduled-task failure.

### 3. Prompt content remains work-conserving and authority-bounded

The canonical prompt SHALL preserve:

- exact-evidence root-cause analysis;
- materially distinct remediation candidates;
- operational-feasibility validation;
- test-first implementation and credential-free verification;
- dependency-advancement handoff in the same invocation;
- control-plane incident recovery;
- the absolute no-early-stop and double-exit-sweep contract;
- documentation fitness across PRD, TRD, ADR, Architecture, UML and ERD applicability;
- one cohesive patch, ten-file and 1,000-line limits; and
- the existing denial of repository write, review, signing, publication and release authority to the model.

This decision SHALL NOT broaden repository-write authority, model tools, egress endpoints, secret names, reviewer identities, dependency permissions, publication credentials or release boundaries.

### 4. Generic failures are resumable control-plane incidents

A **generic scheduled-task failure**, missed expected run, empty previous response, connector/provider failure, or prompt-processing failure is recorded as a **control-plane incident**, not product completion. The next successful invocation re-fetches live automation and GitHub state before acting.

The loop SHALL distinguish only causes supported by observable evidence and SHALL NOT invent a hidden error code. It MAY simplify or correct this same canonical prompt when evidence supports that remedy, but **prompt repair alone** earns zero completion credit. The invocation continues repository work in the same run whenever a safe EgressWeave action remains. A transient provider, connector, tool or rate-limit failure does not disable the recurring loop.

### 5. Verification and maturity

Repository tests SHALL verify the canonical path, size bound, unique no-early-stop and double-exit headings, workflow loader, absence of the old inline heredoc, credentialed-execution prohibition, dependency handoff, control-plane recovery, operator documentation and release-facing changelog entry.

This decision is **ACTIVE-PR** implementation until the scheduler branch that adds the canonical prompt and loader reaches protected main. Protected-main workflow source remains authoritative until then. This ADR remains Proposed until normal review and protected-branch integration accept it.

## Consequences

### Positive

- Prompt growth cannot silently expand the workflow YAML heredoc.
- Workflow syntax and model policy become independently reviewable.
- One bounded prompt source prevents contradictory policy copies.
- Generic scheduler errors have a deterministic recovery path without false completion.
- Moving policy out of YAML reduces the surface for escape and indentation corruption.

### Costs

- The workflow gains another repository-owned file that must be present in checkout and offline verification.
- Prompt changes require the same review rigor as workflow policy changes.
- The 12 KiB budget forces consolidation instead of unlimited historical accumulation.
- External scheduled-task failures still require external telemetry for a definitive scheduler-side RCA.

## Alternatives considered

### Keep the full prompt inline in YAML

Rejected. It couples policy growth to workflow syntax and preserves the failure mode that this decision is intended to reduce.

### Fetch the prompt from another repository at run time

Rejected. It would add mutable cross-repository trust, availability and exact-identity requirements to a credential-bearing workflow.

### Allow the model to rewrite its own prompt

Rejected. Self-modifying policy would collapse the separation between model output and the authority boundary that constrains it.

### Disable the recurring loop after any generic error

Rejected. An unclassified transient error is insufficient evidence that continued execution is unsafe or permanently impossible.

## Related documents

- [ADR 0003](0003-work-conserving-automation-and-dependency-handoff.md) — work conservation, dependency handoff and incident semantics.
- [`../product/PRD.md`](../product/PRD.md) — product and commercial acceptance requirements.
- [`../product/TRD.md`](../product/TRD.md) — technical workflow contract.
- [`../product/OPERABILITY.md`](../product/OPERABILITY.md) — generic scheduler error runbook.
- [`../architecture/SYSTEM_ARCHITECTURE.md`](../architecture/SYSTEM_ARCHITECTURE.md) — control-plane data flow.
- [`../architecture/UML.md`](../architecture/UML.md) — scheduler execution and recovery sequences.
- [`../architecture/ERD.md`](../architecture/ERD.md) — no-owned-persistence boundary.
