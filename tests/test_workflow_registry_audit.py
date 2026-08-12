"""Tests for the read-only GitHub Actions workflow-registry audit."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
AUDITOR_PATH = REPOSITORY_ROOT / "scripts" / "ci" / "audit_workflow_registry.py"
SOURCE_SHA = "0123456789abcdef0123456789abcdef01234567"
OBSERVED_AT = "2026-08-12T12:00:00Z"


def _load_auditor():
    """Load the repository-only audit script from its exact path."""
    specification = importlib.util.spec_from_file_location(
        "egressweave_audit_workflow_registry",
        AUDITOR_PATH,
    )
    assert specification is not None and specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def _workflow(workflow_id: int, path: str, state: str = "active") -> dict[str, object]:
    """Build one minimal workflow-registry fixture."""
    return {"id": workflow_id, "path": path, "state": state, "name": path}


def _page(*workflows: dict[str, object], total_count: int | None = None) -> dict[str, object]:
    """Build one paginated Actions registry response fixture."""
    return {
        "page": 1,
        "total_count": len(workflows) if total_count is None else total_count,
        "workflows": list(workflows),
    }


def test_audit_distinguishes_present_orphan_disabled_and_dynamic_workflows() -> None:
    """Never infer lifecycle state from a workflow display name alone."""
    auditor = _load_auditor()
    result = auditor.build_audit(
        registry_pages=[
            _page(
                _workflow(1, ".github/workflows/ci.yml"),
                _workflow(2, ".github/workflows/old-one-shot.yml"),
                _workflow(3, ".github/workflows/removed.yml", "disabled_manually"),
                _workflow(4, "dynamic/dependabot/update-graph"),
            )
        ],
        present_paths={".github/workflows/ci.yml"},
        active_pr_paths=set(),
        expected_default_sha=SOURCE_SHA,
        observed_default_sha=SOURCE_SHA,
        observed_at=OBSERVED_AT,
    )

    by_id = {record["workflow_id"]: record for record in result["records"]}
    assert by_id[1]["classification"] == "present_repository_workflow"
    assert by_id[2]["classification"] == "active_orphan"
    assert by_id[3]["classification"] == "disabled_absent"
    assert by_id[4]["classification"] == "github_dynamic_workflow"
    assert by_id[2] == {
        "workflow_id": 2,
        "path": ".github/workflows/old-one-shot.yml",
        "state": "active",
        "classification": "active_orphan",
        "default_branch_sha": SOURCE_SHA,
        "observed_at": OBSERVED_AT,
        "registry_page": 1,
    }
    assert result["receipts"] == [{"page": 1, "item_count": 4, "total_count": 4}]


def test_audit_reserves_absent_workflow_owned_by_an_active_pr() -> None:
    """Do not disable a bounded workflow whose source is still owned by an open PR."""
    auditor = _load_auditor()
    result = auditor.build_audit(
        registry_pages=[_page(_workflow(17, ".github/workflows/bounded-pr.yml"))],
        present_paths=set(),
        active_pr_paths={".github/workflows/bounded-pr.yml"},
        expected_default_sha=SOURCE_SHA,
        observed_default_sha=SOURCE_SHA,
        observed_at=OBSERVED_AT,
    )
    assert result["records"][0]["classification"] == "active_pr_reserved"


def test_audit_fails_closed_when_default_branch_moves() -> None:
    """Reject a registry/tree comparison assembled across different protected heads."""
    auditor = _load_auditor()
    with pytest.raises(auditor.AuditError, match="default branch moved"):
        auditor.build_audit(
            registry_pages=[_page(_workflow(1, ".github/workflows/ci.yml"))],
            present_paths={".github/workflows/ci.yml"},
            active_pr_paths=set(),
            expected_default_sha=SOURCE_SHA,
            observed_default_sha="f" * 40,
            observed_at=OBSERVED_AT,
        )


def test_audit_rejects_reused_workflow_id_with_conflicting_path() -> None:
    """Treat workflow-ID reuse or inconsistent pagination as integrity failure."""
    auditor = _load_auditor()
    pages = [
        {
            "page": 1,
            "total_count": 2,
            "workflows": [_workflow(9, ".github/workflows/a.yml")],
        },
        {
            "page": 2,
            "total_count": 2,
            "workflows": [_workflow(9, ".github/workflows/b.yml")],
        },
    ]
    with pytest.raises(auditor.AuditError, match="workflow id 9"):
        auditor.build_audit(
            registry_pages=pages,
            present_paths=set(),
            active_pr_paths=set(),
            expected_default_sha=SOURCE_SHA,
            observed_default_sha=SOURCE_SHA,
            observed_at=OBSERVED_AT,
        )


@pytest.mark.parametrize(
    "path",
    [
        ".Github/workflows/old.yml",
        ".github/workflows/%6fld.yml",
        ".github\\workflows\\old.yml",
        ".github/workflows/../old.yml",
    ],
)
def test_audit_rejects_noncanonical_repository_workflow_paths(path: str) -> None:
    """Reject ambiguous case, encoding, separators, and traversal before classification."""
    auditor = _load_auditor()
    with pytest.raises(auditor.AuditError, match="workflow path"):
        auditor.build_audit(
            registry_pages=[_page(_workflow(1, path))],
            present_paths=set(),
            active_pr_paths=set(),
            expected_default_sha=SOURCE_SHA,
            observed_default_sha=SOURCE_SHA,
            observed_at=OBSERVED_AT,
        )


def test_audit_rejects_truncated_registry_pagination() -> None:
    """Require pagination receipts to account for the complete Actions registry."""
    auditor = _load_auditor()
    with pytest.raises(auditor.AuditError, match="registry pagination"):
        auditor.build_audit(
            registry_pages=[_page(_workflow(1, ".github/workflows/ci.yml"), total_count=2)],
            present_paths={".github/workflows/ci.yml"},
            active_pr_paths=set(),
            expected_default_sha=SOURCE_SHA,
            observed_default_sha=SOURCE_SHA,
            observed_at=OBSERVED_AT,
        )


@pytest.mark.parametrize("status", [403, 404, 500])
def test_request_json_fails_closed_on_permission_or_transport_http_errors(status: int) -> None:
    """Do not turn API permission, disappearance, or server failure into a clean audit."""
    auditor = _load_auditor()

    class Response:
        """Minimal context-managed HTTP response fixture."""

        def __init__(self) -> None:
            self.status = status

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, traceback):
            return False

        def read(self, limit: int) -> bytes:
            return b'{"message":"unavailable"}'

    with pytest.raises(auditor.AuditError, match=f"HTTP {status}"):
        auditor.request_json("https://api.github.invalid/example", opener=lambda request, timeout: Response())


@pytest.mark.parametrize("timeout", [float("nan"), float("inf")])
def test_request_json_rejects_non_finite_timeouts(timeout: float) -> None:
    """Keep control-plane reads bounded by rejecting non-finite socket timeouts."""
    auditor = _load_auditor()

    def unexpected_open(*args, **kwargs):
        pytest.fail("non-finite timeout reached the network opener")

    with pytest.raises(auditor.AuditError, match="timeout is invalid"):
        auditor.request_json(
            "https://api.github.invalid/example",
            opener=unexpected_open,
            timeout=timeout,
        )


def test_collect_registry_pages_is_bounded_and_records_exact_page_numbers() -> None:
    """Collect every advertised workflow without silently truncating the registry."""
    auditor = _load_auditor()
    responses = {
        1: {"total_count": 3, "workflows": [_workflow(1, ".github/workflows/a.yml"), _workflow(2, ".github/workflows/b.yml")]},
        2: {"total_count": 3, "workflows": [_workflow(3, ".github/workflows/c.yml")]},
    }

    def fetch_page(page: int) -> dict[str, object]:
        return responses[page]

    pages = auditor.collect_registry_pages(fetch_page, per_page=2, max_pages=2)
    assert [page["page"] for page in pages] == [1, 2]
    assert sum(len(page["workflows"]) for page in pages) == 3


def test_collect_open_pr_workflow_snapshot_binds_paths_to_exact_heads(monkeypatch) -> None:
    """Include every open PR head so a same-path head replacement is observable."""
    auditor = _load_auditor()

    def fake_request_json(url: str, *, token: str | None = None):
        del token
        if "/pulls?" in url:
            return [
                {"number": 41, "head": {"sha": "a" * 40}},
                {"number": 42, "head": {"sha": "b" * 40}},
            ]
        if "/pulls/41/files?" in url:
            return [
                {"filename": ".github/workflows/new.yml", "status": "added"},
                {"filename": "README.md", "status": "modified"},
            ]
        if "/pulls/42/files?" in url:
            return [{"filename": ".github/workflows/removed.yml", "status": "removed"}]
        raise AssertionError(f"unexpected GitHub API URL: {url}")

    monkeypatch.setattr(auditor, "request_json", fake_request_json)
    assert auditor._collect_open_pr_workflow_snapshot("ContextualWisdomLab/EgressWeave", None) == (
        (41, "a" * 40, (".github/workflows/new.yml",)),
        (42, "b" * 40, ()),
    )


def test_audit_repository_fails_closed_when_open_pr_snapshot_changes(monkeypatch) -> None:
    """Never emit active-PR reservations assembled across different PR heads."""
    auditor = _load_auditor()
    responses = iter(
        [
            {"default_branch": "main"},
            {"commit": {"sha": SOURCE_SHA}},
            [],
            {"commit": {"sha": SOURCE_SHA}},
        ]
    )

    def fake_request_json(url: str, *, token: str | None = None):
        del url, token
        return next(responses)

    monkeypatch.setattr(auditor, "request_json", fake_request_json)
    monkeypatch.setattr(auditor, "collect_registry_pages", lambda fetch_page: [_page()])
    snapshots = iter(
        [
            ((41, "a" * 40, (".github/workflows/new.yml",)),),
            ((41, "b" * 40, (".github/workflows/new.yml",)),),
        ]
    )
    monkeypatch.setattr(
        auditor,
        "_collect_open_pr_workflow_snapshot",
        lambda repository, token: next(snapshots),
        raising=False,
    )
    monkeypatch.setattr(
        auditor,
        "_collect_open_pr_workflow_paths",
        lambda repository, token: {".github/workflows/new.yml"},
        raising=False,
    )

    with pytest.raises(auditor.AuditError, match="pull request workflow reservations changed"):
        auditor.audit_repository(
            "ContextualWisdomLab/EgressWeave",
            SOURCE_SHA,
            observed_at=OBSERVED_AT,
        )


def test_audit_repository_fails_closed_when_workflow_registry_changes(monkeypatch) -> None:
    """Never classify workflow lifecycle state from a registry that changes mid-audit."""
    auditor = _load_auditor()
    responses = iter(
        [
            {"default_branch": "main"},
            {"commit": {"sha": SOURCE_SHA}},
            [],
            {"commit": {"sha": SOURCE_SHA}},
        ]
    )

    def fake_request_json(url: str, *, token: str | None = None):
        del url, token
        return next(responses)

    registry_pages = iter(
        [
            [_page(_workflow(17, ".github/workflows/old.yml", "active"))],
            [_page(_workflow(17, ".github/workflows/old.yml", "disabled_manually"))],
        ]
    )
    monkeypatch.setattr(auditor, "request_json", fake_request_json)
    monkeypatch.setattr(auditor, "collect_registry_pages", lambda fetch_page: next(registry_pages))
    monkeypatch.setattr(auditor, "_collect_open_pr_workflow_snapshot", lambda repository, token: ())

    with pytest.raises(auditor.AuditError, match="workflow registry changed"):
        auditor.audit_repository(
            "ContextualWisdomLab/EgressWeave",
            SOURCE_SHA,
            observed_at=OBSERVED_AT,
        )
