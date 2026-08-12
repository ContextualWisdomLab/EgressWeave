"""Release-workflow contracts for exact protected-main acceptance evidence."""

from __future__ import annotations

from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
RELEASE_WORKFLOW_PATH = REPOSITORY_ROOT / ".github" / "workflows" / "release.yml"


def _release_workflow() -> str:
    """Return the release workflow text used by source-level safety contracts."""
    return RELEASE_WORKFLOW_PATH.read_text(encoding="utf-8")


def _job_block(workflow: str, job_name: str, next_job_name: str) -> str:
    """Return one top-level release job without borrowing text from other jobs."""
    start_marker = f"  {job_name}:"
    end_marker = f"  {next_job_name}:"
    return workflow.split(start_marker, maxsplit=1)[1].split(end_marker, maxsplit=1)[0]


def test_release_publication_requires_exact_workflow_evidence_gate() -> None:
    """Block tag and publication jobs until exact required evidence is verified."""
    workflow = _release_workflow()
    evidence_job = _job_block(
        workflow,
        "verify-release-evidence",
        "create-release-tag",
    )

    assert "name: Verify exact protected-main release evidence" in evidence_job
    assert "permissions:" in evidence_job
    assert "actions: read" in evidence_job
    assert "pull-requests: read" in evidence_job
    assert "checks: read" in evidence_job
    assert "Require integrating pull request for exact release commit" in evidence_job
    assert "Require required workflow evidence for integrating PR head" in evidence_job
    assert "Require executed Dependency review action" in evidence_job
    assert "Require substantive Strix review evidence" in evidence_job

    tag_job = _job_block(workflow, "create-release-tag", "publish-to-pypi")
    assert "- verify-release-evidence" in tag_job

    publish_job = _job_block(workflow, "publish-to-pypi", "publish-github-release")
    assert "- verify-release-evidence" in publish_job

    github_release_job = workflow.split("  publish-github-release:", maxsplit=1)[1]
    assert "- verify-release-evidence" in github_release_job


def test_release_evidence_gate_binds_exact_integrating_pr_and_live_rules() -> None:
    """Require paginated exact-SHA PR evidence and current protected-main rules."""
    workflow = _release_workflow()
    evidence_job = _job_block(
        workflow,
        "verify-release-evidence",
        "create-release-tag",
    )

    assert "commits/${RELEASE_SHA}/pulls?per_page=100" in evidence_job
    assert "--paginate --slurp" in evidence_job
    assert ".merge_commit_sha == $sha" in evidence_job
    assert '.base.ref == "main"' in evidence_job
    assert '[[ "$pr_number" =~ ^[1-9][0-9]*$ ]]' in evidence_job
    assert '[[ "$source_head_sha" =~ ^[0-9a-f]{40}$ ]]' in evidence_job
    assert (
        '[[ "$author_login" =~ '
        '^[A-Za-z0-9]([A-Za-z0-9-]{0,37}[A-Za-z0-9])?$ ]]'
    ) in evidence_job
    assert "rulesets?includes_parents=true&per_page=100" in evidence_job
    assert '.enforcement == "active" and .target == "branch"' in evidence_job
    assert 'select(.type == "workflows")' in evidence_job
    assert ".parameters.workflows[]?" in evidence_job
    assert "repositories/${workflow_repository_id}" in evidence_job
    assert "contents/${workflow_path}?ref=${workflow_ref}" in evidence_job
    assert "actions/runs?head_sha=${SOURCE_HEAD_SHA}&per_page=100" in evidence_job
    assert '.head_sha == $head' in evidence_job
    assert 'workflow_url // ""' in evidence_job
    assert 'required_workflow_url_prefix="https://api.github.com/repos/${GITHUB_REPOSITORY}/actions/required_workflows/"' in evidence_job
    assert 'source_workflow_url_prefix="https://api.github.com/repos/${workflow_source}/actions/workflows/"' in evidence_job
    assert '"$workflow_url" == "${required_workflow_url_prefix}"*' in evidence_job
    assert '"$workflow_url" == "${source_workflow_url_prefix}"*' in evidence_job
    assert '[[ "$workflow_url_id" =~ ^[1-9][0-9]*$ ]]' in evidence_job
    assert "did not bind to the target required-workflow or declared source repository" in evidence_job
    assert "[ \"$(jq -r '.status' <<<\"$latest_run\")\" != \"completed\" ]" in evidence_job
    assert "[ \"$(jq -r '.conclusion' <<<\"$latest_run\")\" != \"success\" ]" in evidence_job


def test_release_evidence_gate_fails_closed_on_review_governance_drift() -> None:
    """Keep current-head approval and thread rules separate from stale evidence."""
    workflow = _release_workflow()

    assert "required_approving_review_count" in workflow
    assert "require_code_owner_review" in workflow
    assert "require_last_push_approval" in workflow
    assert "required_reviewers" in workflow
    assert "pulls/${SOURCE_PR_NUMBER}/reviews?per_page=100" in workflow
    assert '.state == "APPROVED" and .commit_id == $head' in workflow
    assert ".user.login != $author" in workflow
    assert "reviewThreads(first: 100, after: $endCursor)" in workflow
    assert "select(.isResolved == false)" in workflow


def test_release_evidence_gate_rejects_wrapper_green_dependency_review_skip() -> None:
    """Require the real dependency-review action, not only its wrapper job."""
    workflow = _release_workflow()

    assert 'workflow_path" = ".github/workflows/security-scan.yml"' in workflow
    assert "actions/runs/${SECURITY_SCAN_RUN_ID}/jobs?per_page=100" in workflow
    assert '.name == "dependency-review"' in workflow
    assert (
        '.name == "dependency-review" and .status == "completed" '
        'and .conclusion == "success"'
    ) in workflow
    assert (
        '.name == "Dependency review" and .status == "completed" '
        'and .conclusion == "success"'
    ) in workflow
    assert "Pinned Dependency review action was absent, skipped, or non-passing." in workflow


def test_release_evidence_gate_rejects_wrapper_green_unavailable_strix() -> None:
    """Reject a successful required Strix wrapper when no review was produced."""
    workflow = _release_workflow()

    assert 'workflow_path" = ".github/workflows/strix.yml"' in workflow
    assert "Require substantive Strix review evidence" in workflow
    assert ".check_run_url" in workflow
    assert "Strix job did not expose a check-run URL." in workflow
    assert '[[ "$STRIX_CHECK_RUN_URL" =~ ^https://api\\.github\\.com/repos/${GITHUB_REPOSITORY}/check-runs/[0-9]+$ ]]' in workflow
    assert '"${STRIX_CHECK_RUN_URL}/annotations?per_page=100"' in workflow
    assert "check-runs/${strix_check_run_id}/annotations?per_page=100" not in workflow
    assert '.title == "Strix backend unavailable"' in workflow
    assert "Wrapper-green Strix run reported backend-unavailable review evidence." in workflow
