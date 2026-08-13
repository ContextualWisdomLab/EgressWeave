"""Fail-closed regression for partial GitHub API response transfers."""

from __future__ import annotations

import http.client
import importlib.util
from pathlib import Path

import pytest

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
AUDITOR_PATH = REPOSITORY_ROOT / "scripts" / "ci" / "audit_workflow_registry.py"


def _load_auditor():
    """Load the repository-only workflow-registry auditor from its exact path."""
    specification = importlib.util.spec_from_file_location(
        "egressweave_partial_transfer_audit",
        AUDITOR_PATH,
    )
    assert specification is not None and specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def test_request_json_masks_partial_transfer_failure() -> None:
    """A truncated HTTP body must become one generic non-leaking audit failure."""
    auditor = _load_auditor()

    class Response:
        """Context-managed response that aborts after returning partial bytes."""

        status = 200

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, traceback):
            return False

        def read(self, limit: int) -> bytes:
            del limit
            raise http.client.IncompleteRead(b'{"partial":', 100)

    with pytest.raises(auditor.AuditError, match="GitHub API request failed") as captured:
        auditor.request_json(
            "https://api.github.invalid/example",
            opener=lambda request, timeout: Response(),
        )

    assert captured.value.__cause__ is None
    assert captured.value.__context__ is None
