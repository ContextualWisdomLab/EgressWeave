# ADR 0003: Work-conserving automation and dependency handoff

Status: **Proposed**

Date: 2026-08-10

## Context

EgressWeave has two distinct concerns that must not be conflated: product/runtime security and repository automation. The product is an in-process provider-neutral outbound HTTP security library. Repository automation reviews, verifies, prepares or promotes changes around that library, but success or failure in the automation control plane is not itself product state.

Repeated maintenance work exposed two governance failure modes that deserve a durable architecture decision rather than chat-only instructions:

1. a run can stop after one useful action even though another safe EgressWeave action is executable; and
2. a read-only dependency or control-plane incident can be mistaken for whole-run completion even though an EgressWeave-side handoff remains available.

This ADR records the intended governance semantics only. It does **not** claim every repository-local workflow on protected main already implements the target behavior. Automation implementation maturity remains separately classified as `IMPLEMENTED-ON-PROTECTED-MAIN`, `ACTIVE-PR`, `ACCEPTED-TARGET`, or `PLANNED` in the product documentation.

## Decision

### 1. Maintenance is work-conserving

A maintenance invocation SHALL repeatedly choose the highest-value safe executable EgressWeave action from fresh evidence. A merge, review request, RCA, documentation change, test result, queued check, blocked branch, dependency wait, prompt repair or buyer-visible slice is an intermediate event while another safe action exists.

Every completed action hands off to the next executable state in the **same invocation** when practical. The normal handoff chain is:

```text
fresh evidence
-> highest-value safe action
-> exact verification
-> merge or bounded defer decision
-> next executable lane
```

The recurring schedule is continuation after practical invocation/tool-budget exhaustion, not permission to stop after the first useful action.

### 2. Exit requires a double exit sweep

Before an invocation ends, it SHALL perform a **double exit sweep** over open PRs/issues, protected main, changed branches, reviews/checks/security findings, dependency state, documentation fitness, release evidence, integrations and buyer-visible gaps.

If either sweep finds a safe executable EgressWeave action, the invocation continues. Termination is permitted only when the practical invocation/tool budget is genuinely exhausted or a second fresh sweep shows that every remaining lane is non-actionable under current authority, dependency order, repository policy, writer lease and safety constraints.

### 3. Read-only dependencies block only dependent actions

`ContextualWisdomLab/.github`, naruon, contextual-orchestrator and other repositories with independent writer ownership are a **read-only dependency** from the EgressWeave writer loop unless a separate writer lease is explicitly acquired.

A waiting dependency freezes only the affected EgressWeave action. The run rotates to independent EgressWeave work rather than treating the dependency wait as completion.

When a material read-only dependency advances, the EgressWeave loop SHALL:

1. bind the dependency's new **exact identity** (protected/default head or exact PR head);
2. revalidate the specific interface, evidence or acceptance claim that depends on it;
3. update one existing canonical EgressWeave issue/traceability/document only when the delta materially changes acceptance state; and
4. if the prerequisite reaches its protected branch, advance the dependent EgressWeave lane in the **same invocation** by rerunning/revalidating the unchanged affected head, requiring the real repaired gate to execute, or preparing the smallest caller/integration successor allowed by the writer lease.

No stale dependency SHA, PR body, prior review, wrapper status or historical run may be promoted to current acceptance evidence.

### 4. Control-plane errors are incidents, not product completion

A generic scheduled-task failure, connector/provider error, missed expected invocation, or prior automation response that performed no repository work is a **control-plane incident**. On the next successful invocation, the loop SHALL refetch the live automation and GitHub state before relying on remembered blocker claims.

The loop SHALL distinguish observable scheduler/prompt/tool/connector/provider/permission/repository causes without inventing hidden error codes. It MAY simplify or correct the same automation prompt when evidence supports that remedy, but prompt repair alone does not count as repository progress.

A **transient** tool/provider/rate-limit failure SHALL NOT disable the recurring loop. Disabling the loop is reserved for a proven non-transient condition in which continued execution is unsafe or impossible and no other safe EgressWeave work remains.

### 5. Automation does not grant repository-write authority to the model

Work-conserving behavior does not broaden authority. Model execution, verification, review, repository mutation, security scanning, signing/attestation, package publication and release remain distinct trust domains.

This ADR grants no new **repository-write authority**, OIDC authority, credential, signing permission, release permission or reviewer identity. Repository writes must still occur through the existing EgressWeave writer lease and normal branch/ruleset governance. A model-produced patch, automated comment, status, or self-authored review is never independent approval.

### 6. Exact-head evidence remains mandatory

Checks, reviews and scanner evidence are bound to the exact head and the independently resolved live base for which they executed. Queued, pending, skipped-required, cancelled, absent, failed, predecessor-head, synthetic-only, fail-open, rate-limited or comment-only evidence is not a passing gate.

A branch mutation invalidates predecessor-head acceptance evidence and requires the affected gates to execute again on the new exact head.

## Consequences

### Positive

- One blocked PR or read-only dependency no longer starves unrelated safe work.
- Control-plane failures do not silently become product-completion signals.
- Dependency integration produces an explicit same-run caller-side handoff instead of status-only narration.
- Exact-head evidence and writer ownership remain auditable.
- The scheduler can improve its own prompt without creating competing autonomous writers.

### Costs

- Runs perform more fresh state reads and may consume more bounded tool budget.
- Dependency state must be tracked by exact identity rather than informal blocker prose.
- A documentation or prompt update cannot be treated as terminal when executable product/repository work remains.
- Review/check latency still exists; the policy only prevents that latency from unnecessarily idling unrelated lanes.

## Alternatives considered

### Stop after the first material action

Rejected. It systematically leaves safe work unused and converts the recurring schedule into avoidable latency.

### Treat any blocked required gate as a whole-run blocker

Rejected. A required gate blocks the merge/action that depends on it, not unrelated EgressWeave work.

### Duplicate fixes into read-only dependency repositories

Rejected. Competing writers create race conditions, stale evidence and unclear authority. Dependency owners remain authoritative for their repository.

### Disable the automation after a generic error

Rejected for transient or unclassified failures. A generic control-plane error is insufficient evidence that continued execution is unsafe or impossible.

## Implementation maturity

- The decision in this ADR is **Proposed governance**.
- Protected-main workflow behavior remains defined by protected-main source and root `ARCHITECTURE.md`.
- Publisher-removal, RCA/feasibility, verifier-image and related automation changes that are not yet merged remain **ACTIVE-PR** behavior and must not be documented as shipped.
- This ADR becomes an Accepted architecture contract only through normal review and protected-branch integration.

## Related documents

- [`../../ARCHITECTURE.md`](../../ARCHITECTURE.md) — protected-main implementation truth.
- [`../architecture/SYSTEM_ARCHITECTURE.md`](../architecture/SYSTEM_ARCHITECTURE.md) — system and automation authority views.
- [`../architecture/UML.md`](../architecture/UML.md) — sequence/state review aids.
- [`../product/DOCUMENTATION_AUDIT.md`](../product/DOCUMENTATION_AUDIT.md) — documentation fitness and maturity vocabulary.
- [`../product/TRACEABILITY.md`](../product/TRACEABILITY.md) — requirement-to-evidence mapping.
- [`0001-security-boundaries-and-modular-integration.md`](0001-security-boundaries-and-modular-integration.md) — runtime security and modular integration boundary.
- [`0002-documentation-governance-and-persistence-boundary.md`](0002-documentation-governance-and-persistence-boundary.md) — documentation and no-owned-persistence boundary.
