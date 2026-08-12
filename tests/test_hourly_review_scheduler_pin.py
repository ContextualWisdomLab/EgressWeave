"""Regression contract for the cross-repository hourly review scheduler pin."""

from __future__ import annotations

from pathlib import Path


_REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
_WORKFLOW = _REPOSITORY_ROOT / ".github" / "workflows" / "hourly-pr-maintenance.yml"
_PROVEN_CENTRAL_SHA = "5983b41ace75040c1d81818171ca7d0f3653254e"
_OBSOLETE_DIVERGENT_SHA = "74e54255ec903e3ba5f920859b656fe2defcb057"


def test_hourly_review_scheduler_uses_the_proven_central_revision() -> None:
    """Bind both reusable calls to the protected-lineage revision proven in production."""
    workflow = _WORKFLOW.read_text(encoding="utf-8")

    assert (
        "ContextualWisdomLab/.github/.github/workflows/"
        f"pr-review-fix-scheduler.yml@{_PROVEN_CENTRAL_SHA}"
    ) in workflow
    assert (
        "ContextualWisdomLab/.github/.github/workflows/"
        f"pr-review-merge-scheduler.yml@{_PROVEN_CENTRAL_SHA}"
    ) in workflow
    assert _OBSOLETE_DIVERGENT_SHA not in workflow


def test_hourly_review_scheduler_keeps_merge_authority_disabled() -> None:
    """Repair reusable-workflow resolution without restoring autonomous merge authority."""
    workflow = _WORKFLOW.read_text(encoding="utf-8")

    assert "enable_auto_merge: false" in workflow
    assert "merge_mode: disabled" in workflow
