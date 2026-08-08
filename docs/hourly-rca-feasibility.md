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
  protected refs, and branch-protection settings are outside the editable
  boundary;
- executable verification occurs later in a fresh, credential-free, offline
  container and can only produce a digest-bound patch handoff.

Consequently, the product scheduler cannot repair an open pull request, mutate a
central `ContextualWisdomLab/.github` dependency, change a ruleset, manufacture
an approval, or publish a verified patch. Those activities remain owned by the
hourly PR-maintenance path, the relevant repository writer lease, and protected
human or organization controls.

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
