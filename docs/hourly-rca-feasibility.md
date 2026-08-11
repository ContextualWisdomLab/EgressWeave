# Hourly RCA and operational-feasibility contract

The hourly product-development scheduler must not treat the first visible symptom,
failed check, unavailable integration, or external dependency as the root cause.
Before it selects, abandons, or escalates a remediation, the bounded OpenCode
maintainer performs a **root-cause analysis** from the exact evidence available in
the current run and evaluates the **operational feasibility** of each candidate.

## Executable boundary

This contract is deliberately limited to work the repository-local product
scheduler can actually perform:

- the workflow runs only after its paginated gate proves that the repository has
  zero open pull requests;
- the model process has no repository-write, OIDC, release, package,
  attestation, or publication identity;
- model edits are limited to `src/egressweave/**`, `tests/**`, `docs/**`,
  `README.md`, and `CHANGELOG.md`;
- `.github/**`, `scripts/**`, dependencies, build configuration, credentials,
  protected refs, and branch-protection settings are outside the model-editable
  boundary;
- executable verification occurs later in a fresh, credential-free, offline
  container and can only produce a digest-bound patch handoff.

Consequently, the product scheduler cannot repair an open pull request, mutate a
central `ContextualWisdomLab/.github` dependency, change a ruleset, manufacture
an approval, or publish a verified patch. Those activities remain owned by the
hourly PR-maintenance path, the relevant repository writer lease, and protected
human or organization controls.

## Canonical prompt and control-plane budget

The executable maintainer policy is stored once in the repository-owned canonical
prompt at `.github/prompts/hourly-product-maintainer.md`. The workflow copies that
regular, non-symlink file into its private runner directory and rejects it before
model execution when it exceeds the explicit **12 KiB** control-plane budget.
The workflow no longer embeds the full policy in a YAML heredoc, reducing both
prompt duplication and the risk that prompt growth or escape/newline damage
breaks workflow parsing.

The 12 KiB limit is an engineering control for the repository-local OpenCode
handoff, not evidence about an unobservable external scheduler limit. A generic
scheduled-task error has no trustworthy hidden error code in repository state.
It is therefore classified as a **control-plane incident** until exact evidence
identifies a narrower scheduler, connector, provider, permission, prompt, or
repository cause.

On the next executable invocation, the maintainer re-fetches live repository
state, revalidates any dependency advancement, and continues repository work in
the same invocation. Prompt repair alone earns zero completion credit. A
transient tool, provider, rate-limit, or connector failure does not disable the
recurring loop.

## Decision procedure

For one candidate gap or failed protected-branch behavior, the maintainer must:

1. identify the exact observed evidence and trace it backward to the earliest
   cause supported by repository state rather than guessing from the symptom;
2. enumerate the smallest evidence-backed remediation candidates;
3. evaluate each candidate against the exact checkout, available permissions and
   tools, writer leases, branch protection, required checks, dependency order,
   allowed edit paths, file and diff limits, and remaining run time;
4. reject a candidate as infeasible when the required authority, evidence,
   dependency, or validation cannot exist inside this run;
5. execute the smallest safe candidate that is both technically sound and
   operationally realistic, preserving test-first ordering;
6. when the preferred candidate is infeasible, record the exact reason in the
   model result and continue with the next non-conflicting bounded action instead
   of stopping at the first blocker; and
7. escalate only after **every autonomously actionable path has been exhausted**.

A queued review, stale dependency, or unavailable external writer does not make
an unrelated in-scope action unsafe. Conversely, the instruction to continue is
not authority to cross a writer lease, weaken a test, bypass branch protection,
change credentials, or replace missing evidence with an assertion.

## Work-conserving continuation inside one patch

The bounded maintainer is **work-conserving** within the one cohesive product
slice selected for the run. After every completed or deferred sub-action it must
reassess what safe material work remains inside that same slice instead of
stopping because one candidate is blocked, one fix is complete, or one
publication-independent documentation artifact has been updated.

The reassessment includes product behavior, tests, security and reliability,
release-readiness evidence, and **documentation completeness**. For a material
architecture or product-boundary change it must inspect the applicability of
**PRD, TRD, ADR, Architecture, UML, and ERD** records as well as directly related
operator guidance. An ERD may be explicitly not applicable when the core owns
**no persistence**; the scheduler must document that boundary rather than invent
a database merely to satisfy a document checklist.

Continuation never broadens the patch into unrelated opportunistic work. The
one-slice, ten-file, and 1,000-line limits still apply, and the maintainer must
leave unrelated findings for later governed work. It may leave the working tree
unchanged only when no safe material improvement remains inside the allowed edit
boundary for the selected slice, or when every remaining action would require
forbidden authority or exceed the bounded validation contract.

## Read-only dependency handoff

A material change in `.github`, naruon, contextual-orchestrator, or another
independently owned dependency is not a status-only event. The maintainer binds
the new exact protected/default or PR head, revalidates the affected interface or
claim, and advances any permitted EgressWeave-side handoff in the same invocation.
A dependency wait never terminates the run while a safe local caller-side test,
documentation correction, or exact-evidence update remains executable.

## Protected-branch failure

If protected `main` is not green, restoring it is the only permitted objective
only when the root-cause analysis shows that the defect is inside the scheduler's
allowed edit boundary and can be validated within the current run. If the cause
requires a workflow, central-control-plane, credential, permission, ruleset,
review, or publication change, the maintainer leaves the working tree unchanged,
records the evidence and infeasibility reason, and does not pretend that a local
patch can close the incident.

## Evidence retained

The OpenCode NDJSON result is retained with the untrusted pre-verification
artifact. It should identify the observed symptom, supported root cause,
candidates considered, feasibility decision, chosen bounded action, and any
remaining external authority. Successful offline reverification proves only the
exact patch and base combination; it does not prove approval, mergeability,
publication authority, or operational incident closure.
