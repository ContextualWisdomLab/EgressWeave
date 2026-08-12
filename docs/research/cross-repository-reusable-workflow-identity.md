# Cross-repository reusable-workflow identity

## Decision

The hourly PR-maintenance workflow calls both organization-owned schedulers by
their full repository path and an immutable commit SHA:

```text
ContextualWisdomLab/.github/.github/workflows/pr-review-fix-scheduler.yml@5983b41ace75040c1d81818171ca7d0f3653254e
ContextualWisdomLab/.github/.github/workflows/pr-review-merge-scheduler.yml@5983b41ace75040c1d81818171ca7d0f3653254e
```

The SHA is the dependency identity, not a new integration boundary. The
caller still owns the same job permissions, inputs, and `secrets: inherit`
contract. The merge job explicitly keeps `enable_auto_merge` false and
`merge_mode` disabled, so this repair cannot grant autonomous merge authority.

The regression test extracts the `jobs` mapping and compares the `uses` and
`with` values inside the two named jobs. A repository-wide text search is not
sufficient evidence because a comment or unrelated job could contain the same
string without changing the executed reusable workflow.

## Security rationale

GitHub Actions resolves a reusable workflow from the called repository and
reference. A full commit SHA makes that reference immutable for the caller;
the central repository remains responsible for reviewing the implementation at
that commit. The caller must still restrict permissions and treat inherited
secrets as a deliberate trust boundary. Pinning does not turn a workflow into a
sandbox, add an approval, or authorize a merge.

Post-merge acceptance should therefore inspect the completed run's
`referenced_workflows` evidence and confirm that both calls resolve to the
reviewed SHA. A green caller check alone is not proof of the executed central
workflow identity.

## References

GitHub. (n.d.). *Reusing workflows*. GitHub Docs. Retrieved August 12, 2026,
from https://docs.github.com/en/actions/sharing-automations/reusing-workflows

GitHub. (n.d.). *Security hardening for GitHub Actions*. GitHub Docs. Retrieved
August 12, 2026, from
https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions
