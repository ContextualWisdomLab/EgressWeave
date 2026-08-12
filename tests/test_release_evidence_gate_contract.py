"""Release-workflow contracts for exact protected-main acceptance evidence."""

from __future__ import annotations

from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
RELEASE_WORKFLOW_PATH = REPOSITORY_ROOT / ".github" / "workflows" / "release.yml"


def _release_workflow() -> str:
    """Return the release workflow text used by source-level safety contracts."""
    return RELEASE_WORKFLOW_PATH.read_text(encoding="utf-8")


def test_release_publication_requires_exact_workflow_evidence_gate() -> None:
    """Block tag and publication jobs until exact required evidence is verified."""
    workflow = _release_workflow()

    assert "  verify-release-evidence:" in workflow
    assert "name: Verify exact protected-main release evidence" in workflow
    assert "permissions:" in workflow
    assert "actions: read" in workflow
    assert "pull-requests: read" in workflow
    assert "checks: read" in workflow
    assert "Require integrating pull request for exact release commit" in workflow
    assert "Require required workflow evidence for integrating PR head" in workflow
    assert "Require executed Dependency review action" in workflow

    tag_job = workflow.split("  create-release-tag:", maxsplit=1)[1].split(
        "  publish-to-pypi:", maxsplit=1
    )[0]
    assert "- verify-release-evidence" in tag_job

    publish_job = workflow.split("  publish-to-pypi:", maxsplit=1)[1].split(
        "  publish-github-release:", maxsplit=1
    )[0]
    assert "- verify-release-evidence" in publish_job

    github_release_job = workflow.split("  publish-github-release:", maxsplit=1)[1]
    assert "- verify-release-evidence" in github_release_job


def test_release_evidence_gate_binds_exact_integrating_pr_and_live_rules() -> None:
    """Require paginated exact-SHA PR evidence and current protected-main rules."""
    workflow = _release_workflow()

    assert "commits/${RELEASE_SHA}/pulls?per_page=100" in workflow
    assert "--paginate --slurp" in workflow
    assert ".merge_commit_sha == $sha" in workflow
    assert '.base.ref == "main"' in workflow
    assert '[[ "$source_head_sha" =~ ^[0-9a-f]{40}$ ]]' in workflow
    assert "rulesets?includes_parents=true&per_page=100" in workflow
    assert '.enforcement == "active" and .target == "branch"' in workflow
    assert 'select(.type == "workflows")' in workflow
    assert ".parameters.workflows[]?" in workflow
    assert "actions/runs?head_sha=${SOURCE_HEAD_SHA}&per_page=100" in workflow
    assert '.head_sha == $head' in workflow
    assert '.status' in workflow
    assert '.conclusion' in workflow
    assert 'contains("/actions/required_workflows/")' in workflow


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
    assert '.name == "dependency-review" and .status == "completed" and .conclusion == "success"' in workflow
    assert '.name == "Dependency review" and .status == "completed" and .conclusion == "success"' in workflow
    assert "Pinned Dependency review action was absent, skipped, or non-passing." in workflow
