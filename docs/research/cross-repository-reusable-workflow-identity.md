# Cross-repository reusable-workflow identity

## Decision

The hourly PR-maintenance workflow calls both organization-owned schedulers by
their full repository path and an immutable commit SHA:

```text
ContextualWisdomLab/.github/.github/workflows/pr-review-fix-scheduler.yml@59505c1d89eb7ea816e921b6da38079c736608c2
ContextualWisdomLab/.github/.github/workflows/pr-review-merge-scheduler.yml@59505c1d89eb7ea816e921b6da38079c736608c2
```

The SHA is the dependency identity, not a new integration boundary. The
caller still owns the same job permissions and inputs. The central revision
declares the two optional review credentials, and each caller job maps only
`PR_REVIEW_MERGE_TOKEN` and `OPENCODE_APPROVE_TOKEN`; it does not use
`secrets: inherit`. The merge job explicitly keeps `enable_auto_merge` false
and `merge_mode` disabled, so this repair cannot grant autonomous merge
authority.

The regression test extracts the `jobs` mapping and compares the `uses` and
`with` values inside the two named jobs. A repository-wide text search is not
sufficient evidence because a comment or unrelated job could contain the same
string without changing the executed reusable workflow.

## Security rationale

GitHub Actions resolves a reusable workflow from the called repository and
reference. A full commit SHA makes that reference immutable for the caller;
the central repository remains responsible for reviewing the implementation at
that commit. The caller must still restrict permissions and treat the
explicitly mapped review credentials as a deliberate trust boundary; the
mapping prevents unrelated secrets from being inherited. Pinning does not turn
a workflow into a sandbox, add an approval, or authorize a merge.

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
