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

For this decision, the terms are machine-checkable governance concepts rather than informal prose:

- A **fresh snapshot** is the current-invocation observation taken after the latest relevant mutation and containing protected-main identity, every affected PR head, each independently resolved live base tip, dependency ancestry, current reviews/threads/checks, the target ref/blob where a write is contemplated, and active-writer evidence. A snapshot is stale as soon as any identity it binds is observed to move; the affected lane must be refetched before selection or mutation.
- A **safe action** is an action permitted by the EgressWeave writer lease, live repository policy and safety constraints that does not race another writer, invent credentials or approval, weaken a required gate, write a read-only dependency, or knowingly leave the target in an unrecoverable state.
- An **executable action** is a safe action for which the current tool/API supports the operation, the actor has the required authority, all prerequisite dependency/ancestry conditions are presently satisfied, no active-writer conflict owns the target, and an observable bounded acceptance proof can be obtained or intentionally deferred by exact identity.
- **Highest-value** is determined by the deterministic lane priority below, not by narrative preference.

The **deterministic lane priority** is: (1) merge an unchanged exact-head gate-clean PR; (2) fix a valid current security/product/reliability/data-integrity/test defect; (3) remove an EgressWeave-owned CI/workflow/review/stack/release blocker; (4) resolve addressed review threads or close a proven duplicate/superseded item; (5) finish Draft or stacked work in dependency order; (6) advance another non-conflicting accepted issue or integration; (7) perform protected-main operational acceptance; (8) repair canonical documentation or traceability drift; (9) strengthen coverage, docstrings, security, privacy, reliability, observability, accessibility, packaging, SBOM, provenance or release evidence; and (10) implement the highest-impact bounded buyer-visible gap.

Within one priority class, the **tie-break** order is: required stack/dependency predecessor first; then the action that unblocks the greatest number of currently known lanes; then higher consequence class (`security/privacy/data integrity` before `availability/reliability`, before `correctness/interoperability`, before `operability/release`, before `documentation`); then the older canonical PR or issue number; and finally lexical branch/path identity when no numbered item exists. A newly discovered higher-priority defect preempts a lower-priority lane only after the current atomic mutation has reached a safe checkpoint.

Every completed action hands off to the next executable state in the **same invocation** when practical. Here, **when practical** means the next atomic action can reach either acceptance proof or a safe, exact-identity defer point within the observable invocation/tool budget without violating the writer lease or repository policy. The normal handoff chain is:

```text
fresh evidence
-> selected action from deterministic priority
-> exact verification
-> merge or bounded defer decision
-> next executable lane
```

A **handoff may be skipped only** when the affected lane has become non-actionable because of one of these finite conditions: an unsatisfied read-only dependency; a current writer-lease conflict; a required external permission or qualifying approval with no autonomous substitute; a safety/repository-policy prohibition; missing tool/API capability or actor authority with no supported alternative; or genuine practical invocation/tool-budget exhaustion before another atomic action can reach a safe checkpoint. The run SHALL rotate around every lane-specific condition except the final budget condition.

For every selection and bounded defer, acceptance evidence SHALL record the **selected action**, the fresh snapshot identities that justified it, and the resulting handoff/defer reason. This is control-plane evidence only; it does not create a product persistence obligation for the EgressWeave library.

The recurring schedule is continuation after practical invocation/tool-budget exhaustion, not permission to stop after the first useful action.

### 2. Exit requires a double exit sweep

Before an invocation ends, it SHALL perform a **double exit sweep** over open PRs/issues, protected main, changed branches, reviews/checks/security findings, dependency state, documentation fitness, release evidence, integrations and buyer-visible gaps.

Each sweep is based on a new **fresh snapshot** captured after the most recent mutation or defer decision. The second sweep may not reuse the first sweep's head/base/check/review identities. If either sweep finds a safe executable EgressWeave action, the invocation continues and the sweep count resets.

A lane is **non-actionable** only when fresh evidence maps it to one of the finite handoff-skip conditions defined above and no independent EgressWeave action in the deterministic lane priority remains executable. Waiting, queued CI, provider rate limits, one blocked branch, one read-only dependency or one missing approval do not make unrelated lanes non-actionable.

**Termination is permitted only** when either (a) the practical invocation/tool budget is genuinely exhausted before another atomic action can reach a safe checkpoint, or (b) two consecutive fresh sweeps show that every remaining lane is non-actionable under current authority, dependency order, repository policy, writer lease and safety constraints.

The final acceptance evidence SHALL record the last **selected action** (if any), the identities used for both exit sweeps, and a finite **termination reason** matching one of the two conditions above. A generic progress summary, documentation update, prompt repair or unchanged blocker is not a termination reason.

### 3. Read-only dependencies block only dependent actions

`ContextualWisdomLab/.github`, naruon, contextual-orchestrator and other repositories with independent writer ownership are a **read-only dependency** from the EgressWeave writer loop unless a separate writer lease is explicitly acquired.

A waiting dependency freezes only the affected EgressWeave action. The run rotates to independent EgressWeave work rather than treating the dependency wait as completion.

When a material read-only dependency advances, the EgressWeave loop SHALL:

1. bind the dependency's new **exact identity** (protected/default head or exact PR head);
2. revalidate the specific interface, evidence or acceptance claim that depends on it;
3. refetch the dependent EgressWeave exact head, independently resolved live base, gates and writer lease before handoff;
4. update one existing canonical EgressWeave issue/traceability/document only when the delta materially changes acceptance state; and
5. if the prerequisite reaches its protected branch and the dependent identity still matches, advance the dependent EgressWeave lane in the **same invocation** by rerunning/revalidating the unchanged affected head, requiring the real repaired gate to execute, or preparing the smallest caller/integration successor allowed by the writer lease. If the dependent identity, gates or lease no longer match, freeze that action and rotate instead of executing a stale handoff.

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

Acceptance evidence is invalidated whenever the **head or independently resolved live base identity changes**. The affected gates SHALL execute again for the **new head-and-live-base combination**, including the case where the candidate branch head is unchanged but protected main advances. A branch mutation therefore invalidates predecessor-head evidence, and a live-base-only movement invalidates predecessor-base evidence.

## Consequences

### Positive

- One blocked PR or read-only dependency no longer starves unrelated safe work.
- Control-plane failures do not silently become product-completion signals.
- Dependency integration produces an explicit same-run caller-side handoff instead of status-only narration.
- Exact-head and current-live-base evidence plus writer ownership remain auditable.
- Selection and termination are deterministic enough to regression-test rather than depending on informal wording.
- The scheduler can improve its own prompt without creating competing autonomous writers.

### Costs

- Runs perform more fresh state reads and may consume more bounded tool budget.
- Dependency state must be tracked by exact identity rather than informal blocker prose.
- Priority and tie-break rules must be updated deliberately if repository governance changes.
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
