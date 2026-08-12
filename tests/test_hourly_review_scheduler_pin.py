"""Regression contract for the cross-repository hourly review scheduler pin."""

from __future__ import annotations

from pathlib import Path
from typing import Any

_REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
_WORKFLOW = _REPOSITORY_ROOT / ".github" / "workflows" / "hourly-pr-maintenance.yml"
_CENTRAL_REVIEW_FIX_SHA = "59505c1d89eb7ea816e921b6da38079c736608c2"
_PREVIOUS_CENTRAL_SHA = "5983b41ace75040c1d81818171ca7d0f3653254e"
_OBSOLETE_DIVERGENT_SHA = "74e54255ec903e3ba5f920859b656fe2defcb057"


def _parse_scalar(value: str) -> bool | str:
    """Parse the small YAML scalar subset used by the scheduler contract."""
    value = value.strip()
    if value == "true":
        return True
    if value == "false":
        return False
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
        return value[1:-1]
    return value


def _parse_workflow_jobs(workflow: str) -> dict[str, dict[str, Any]]:
    """Extract actual job fields without accepting decoy text from comments or peers."""
    lines = workflow.splitlines()
    jobs: dict[str, dict[str, Any]] = {}
    in_jobs = False
    current_job: dict[str, Any] | None = None
    current_nested: dict[str, Any] | None = None

    for line in lines:
        if not in_jobs:
            if line == "jobs:":
                in_jobs = True
            continue

        if line and not line.startswith(" "):
            break
        if not line.strip() or line.lstrip().startswith("#"):
            continue

        if line.startswith("  ") and not line.startswith("    ") and line.endswith(":"):
            job_name = line.strip()[:-1]
            current_job = {}
            jobs[job_name] = current_job
            current_nested = None
            continue

        if current_job is None:
            continue

        if line.startswith("    ") and not line.startswith("      "):
            key, separator, value = line.strip().partition(":")
            if not separator:
                continue
            if value.strip():
                current_job[key] = _parse_scalar(value)
                current_nested = None
            else:
                current_nested = {}
                current_job[key] = current_nested
            continue

        if line.startswith("      ") and current_nested is not None:
            key, separator, value = line.strip().partition(":")
            if separator:
                current_nested[key] = _parse_scalar(value)

    return jobs


def test_job_parser_ignores_decoy_text_outside_actual_target_fields() -> None:
    """Prevent comments or unrelated jobs from satisfying the scheduler contract."""
    workflow = f"""
jobs:
  decoy:
    uses: ContextualWisdomLab/.github/.github/workflows/pr-review-fix-scheduler.yml@{_CENTRAL_REVIEW_FIX_SHA}
  fix-review-feedback:
    uses: ContextualWisdomLab/.github/.github/workflows/pr-review-fix-scheduler.yml@wrong
    # ContextualWisdomLab/.github/.github/workflows/pr-review-fix-scheduler.yml@{_CENTRAL_REVIEW_FIX_SHA}
  review-recheck-and-merge:
    uses: ContextualWisdomLab/.github/.github/workflows/pr-review-merge-scheduler.yml@wrong
    with:
      enable_auto_merge: true
      merge_mode: direct
# ContextualWisdomLab/.github/.github/workflows/pr-review-merge-scheduler.yml@{_CENTRAL_REVIEW_FIX_SHA}
# enable_auto_merge: false
# merge_mode: disabled
"""
    jobs = _parse_workflow_jobs(workflow)

    assert jobs["fix-review-feedback"]["uses"].endswith("@wrong")
    assert jobs["review-recheck-and-merge"]["uses"].endswith("@wrong")
    assert jobs["review-recheck-and-merge"]["with"] == {
        "enable_auto_merge": True,
        "merge_mode": "direct",
    }


def test_hourly_review_scheduler_uses_the_central_secret_contract_revision() -> None:
    """Bind both reusable calls to the central revision with the secret contract."""
    jobs = _parse_workflow_jobs(_WORKFLOW.read_text(encoding="utf-8"))
    fix_job = jobs["fix-review-feedback"]
    merge_job = jobs["review-recheck-and-merge"]

    expected_fix = (
        "ContextualWisdomLab/.github/.github/workflows/"
        f"pr-review-fix-scheduler.yml@{_CENTRAL_REVIEW_FIX_SHA}"
    )
    expected_merge = (
        "ContextualWisdomLab/.github/.github/workflows/"
        f"pr-review-merge-scheduler.yml@{_CENTRAL_REVIEW_FIX_SHA}"
    )
    assert fix_job["uses"] == expected_fix
    assert merge_job["uses"] == expected_merge
    assert _PREVIOUS_CENTRAL_SHA not in {fix_job["uses"], merge_job["uses"]}
    assert _OBSOLETE_DIVERGENT_SHA not in {fix_job["uses"], merge_job["uses"]}


def test_hourly_review_scheduler_passes_only_named_review_secrets() -> None:
    """Keep the caller boundary least-privilege for both reusable jobs."""
    jobs = _parse_workflow_jobs(_WORKFLOW.read_text(encoding="utf-8"))
    expected = {
        "PR_REVIEW_MERGE_TOKEN": "${{ secrets.PR_REVIEW_MERGE_TOKEN }}",
        "OPENCODE_APPROVE_TOKEN": "${{ secrets.OPENCODE_APPROVE_TOKEN }}",
    }

    assert jobs["fix-review-feedback"]["secrets"] == expected
    assert jobs["review-recheck-and-merge"]["secrets"] == expected


def test_hourly_review_scheduler_keeps_merge_authority_disabled() -> None:
    """Repair reusable-workflow resolution without restoring autonomous merge authority."""
    jobs = _parse_workflow_jobs(_WORKFLOW.read_text(encoding="utf-8"))
    merge_with = jobs["review-recheck-and-merge"]["with"]

    assert isinstance(merge_with, dict)
    assert merge_with["enable_auto_merge"] is False
    assert merge_with["merge_mode"] == "disabled"
