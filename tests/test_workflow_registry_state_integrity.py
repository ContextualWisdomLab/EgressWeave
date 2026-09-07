"""Fail-closed workflow-state regression for the registry auditor."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
AUDITOR_PATH = REPOSITORY_ROOT / "scripts" / "ci" / "audit_workflow_registry.py"
SOURCE_SHA = "0123456789abcdef0123456789abcdef01234567"


def _load_auditor():
    """Load the repository-only workflow-registry auditor from its exact path."""
    specification = importlib.util.spec_from_file_location(
        "egressweave_workflow_state_audit",
        AUDITOR_PATH,
    )
    assert specification is not None and specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def test_audit_rejects_unknown_workflow_state() -> None:
    """Do not silently classify an unknown lifecycle state as safely disabled."""
    auditor = _load_auditor()
    page = {
        "page": 1,
        "total_count": 1,
        "workflows": [
            {
                "id": 7,
                "path": ".github/workflows/removed.yml",
                "state": "provider_future_state",
            }
        ],
    }

    with pytest.raises(auditor.AuditError, match="workflow state is invalid"):
        auditor.build_audit(
            registry_pages=[page],
            present_paths=set(),
            active_pr_paths=set(),
            expected_default_sha=SOURCE_SHA,
            observed_default_sha=SOURCE_SHA,
            observed_at="2026-08-13T03:30:00Z",
        )
