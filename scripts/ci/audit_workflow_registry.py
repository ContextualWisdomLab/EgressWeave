"""Audit GitHub Actions workflow identities without mutating repository state.

GitHub keeps an Actions workflow identity independently from the workflow YAML
that originally created it.  Removing a temporary workflow file therefore does
not prove that the corresponding registry identity was disabled.  This module
builds a bounded, exact-revision audit that keeps those two authorities separate.

The script is intentionally read-only.  It never disables a workflow, updates a
branch, comments on a pull request, or requests additional credentials.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Iterable, Mapping
from datetime import datetime, timezone
from typing import Any

API_ROOT = "https://api.github.com"
WORKFLOW_PREFIX = ".github/workflows/"
DYNAMIC_PREFIX = "dynamic/"
MAX_RESPONSE_BYTES = 8 * 1024 * 1024
DEFAULT_TIMEOUT_SECONDS = 10.0
DEFAULT_PER_PAGE = 100
DEFAULT_MAX_PAGES = 100
DEFAULT_MAX_PR_PAGES = 10
DEFAULT_MAX_PR_FILE_PAGES = 10
_REPOSITORY_PATTERN = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_SHA_PATTERN = re.compile(r"^[0-9a-f]{40}$")


class AuditError(RuntimeError):
    """Report an incomplete or internally inconsistent workflow audit."""


def _require_sha(value: object, *, label: str) -> str:
    """Return one exact lowercase Git commit SHA or fail closed."""
    if not isinstance(value, str) or _SHA_PATTERN.fullmatch(value) is None:
        raise AuditError(f"{label} is not an exact commit SHA")
    return value


def _require_repository(value: str) -> str:
    """Validate the public ``owner/repository`` identifier used in API paths."""
    if _REPOSITORY_PATTERN.fullmatch(value) is None:
        raise AuditError("repository identity is invalid")
    return value


def _require_workflow_path(value: object) -> str:
    """Validate one canonical Actions registry path before classification."""
    if not isinstance(value, str) or not value or value != value.strip():
        raise AuditError("workflow path is invalid")
    if "\\" in value or "%" in value:
        raise AuditError("workflow path is not canonical")
    if value.startswith(DYNAMIC_PREFIX):
        if any(segment in {"", ".", ".."} for segment in value.split("/")):
            raise AuditError("workflow path is not canonical")
        return value
    if not value.startswith(WORKFLOW_PREFIX):
        raise AuditError("workflow path is not canonical")
    filename = value[len(WORKFLOW_PREFIX) :]
    if (
        not filename
        or "/" in filename
        or filename in {".", ".."}
        or not filename.endswith((".yml", ".yaml"))
    ):
        raise AuditError("workflow path is not canonical")
    return value


def _require_workflow_id(value: object) -> int:
    """Return a positive GitHub workflow ID without accepting booleans."""
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise AuditError("workflow id is invalid")
    return value


def _require_total_count(value: object) -> int:
    """Return a non-negative registry total count."""
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise AuditError("workflow registry total_count is invalid")
    return value


def _request_status(response: object) -> int:
    """Read an HTTP status from a normal urllib-style response."""
    status = getattr(response, "status", None)
    if status is None:
        getcode = getattr(response, "getcode", None)
        if callable(getcode):
            status = getcode()
    if isinstance(status, bool) or not isinstance(status, int):
        raise AuditError("GitHub API response has no valid HTTP status")
    return status


def request_json(
    url: str,
    *,
    token: str | None = None,
    opener: Callable[..., Any] = urllib.request.urlopen,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
) -> Any:
    """Fetch one bounded GitHub JSON response and fail closed on API errors.

    ``token`` is used only as a bearer header for the current request and is
    never copied into output or diagnostics.
    """
    if not isinstance(timeout, (int, float)) or isinstance(timeout, bool):
        raise AuditError("GitHub API timeout is invalid")
    try:
        canonical_timeout = float(timeout)
    except (OverflowError, ValueError):
        raise AuditError("GitHub API timeout is invalid") from None
    if not math.isfinite(canonical_timeout) or canonical_timeout <= 0:
        raise AuditError("GitHub API timeout is invalid")
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "EgressWeave-workflow-registry-audit",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with opener(request, timeout=canonical_timeout) as response:
            status = _request_status(response)
            if status != 200:
                raise AuditError(f"GitHub API returned HTTP {status}")
            payload = response.read(MAX_RESPONSE_BYTES + 1)
    except AuditError:
        raise
    except urllib.error.HTTPError as exc:
        raise AuditError(f"GitHub API returned HTTP {exc.code}") from None
    except (urllib.error.URLError, TimeoutError, OSError):
        raise AuditError("GitHub API request failed") from None
    if len(payload) > MAX_RESPONSE_BYTES:
        raise AuditError("GitHub API response exceeds the audit safety bound")
    try:
        return json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise AuditError("GitHub API returned malformed JSON") from None


def collect_registry_pages(
    fetch_page: Callable[[int], Mapping[str, object]],
    *,
    per_page: int = DEFAULT_PER_PAGE,
    max_pages: int = DEFAULT_MAX_PAGES,
) -> list[dict[str, object]]:
    """Collect the complete Actions workflow registry within explicit bounds."""
    if per_page <= 0 or per_page > 100 or max_pages <= 0:
        raise AuditError("workflow registry pagination bounds are invalid")
    pages: list[dict[str, object]] = []
    expected_total: int | None = None
    collected = 0
    for page_number in range(1, max_pages + 1):
        raw_page = fetch_page(page_number)
        if not isinstance(raw_page, Mapping):
            raise AuditError("workflow registry page is malformed")
        total_count = _require_total_count(raw_page.get("total_count"))
        workflows = raw_page.get("workflows")
        if not isinstance(workflows, list) or len(workflows) > per_page:
            raise AuditError("workflow registry page is malformed")
        if expected_total is None:
            expected_total = total_count
        elif total_count != expected_total:
            raise AuditError("workflow registry total_count changed during pagination")
        pages.append(
            {
                "page": page_number,
                "total_count": total_count,
                "workflows": list(workflows),
            }
        )
        collected += len(workflows)
        if collected == expected_total:
            return pages
        if collected > expected_total or not workflows:
            raise AuditError("workflow registry pagination is incomplete")
    raise AuditError("workflow registry pagination exceeded the safety bound")


def _validated_known_paths(paths: Iterable[str]) -> set[str]:
    """Validate repository workflow paths supplied by tree or PR evidence."""
    validated: set[str] = set()
    for path in paths:
        validated.add(_require_workflow_path(path))
    return validated


def build_audit(
    *,
    registry_pages: Iterable[Mapping[str, object]],
    present_paths: Iterable[str],
    active_pr_paths: Iterable[str],
    expected_default_sha: str,
    observed_default_sha: str,
    observed_at: str,
) -> dict[str, object]:
    """Classify exact workflow identities against one immutable repository view.

    A repository workflow is an ``active_orphan`` only when its registry path is
    active, absent from the protected tree, and not reserved by an open pull
    request.  GitHub-owned ``dynamic/...`` identities are deliberately separated
    from repository workflow lifecycle state.
    """
    expected_sha = _require_sha(expected_default_sha, label="expected default branch")
    observed_sha = _require_sha(observed_default_sha, label="observed default branch")
    if expected_sha != observed_sha:
        raise AuditError("default branch moved during workflow registry audit")
    if not isinstance(observed_at, str) or not observed_at:
        raise AuditError("workflow registry observation time is invalid")

    present = _validated_known_paths(present_paths)
    reserved = _validated_known_paths(active_pr_paths)
    pages = list(registry_pages)
    if not pages:
        raise AuditError("workflow registry pagination is incomplete")

    expected_total: int | None = None
    seen_ids: dict[int, tuple[str, str]] = {}
    records: list[dict[str, object]] = []
    receipts: list[dict[str, int]] = []
    item_count = 0

    for expected_page_number, raw_page in enumerate(pages, start=1):
        if not isinstance(raw_page, Mapping):
            raise AuditError("workflow registry page is malformed")
        page_number = raw_page.get("page")
        if page_number != expected_page_number:
            raise AuditError("workflow registry pagination is inconsistent")
        total_count = _require_total_count(raw_page.get("total_count"))
        workflows = raw_page.get("workflows")
        if not isinstance(workflows, list):
            raise AuditError("workflow registry page is malformed")
        if expected_total is None:
            expected_total = total_count
        elif total_count != expected_total:
            raise AuditError("workflow registry total_count changed during pagination")

        receipts.append(
            {
                "page": expected_page_number,
                "item_count": len(workflows),
                "total_count": total_count,
            }
        )
        item_count += len(workflows)
        for workflow in workflows:
            if not isinstance(workflow, Mapping):
                raise AuditError("workflow registry item is malformed")
            workflow_id = _require_workflow_id(workflow.get("id"))
            path = _require_workflow_path(workflow.get("path"))
            state = workflow.get("state")
            if not isinstance(state, str) or not state:
                raise AuditError("workflow state is invalid")
            prior = seen_ids.get(workflow_id)
            identity = (path, state)
            if prior is not None:
                raise AuditError(f"workflow id {workflow_id} appears more than once")
            seen_ids[workflow_id] = identity

            if path.startswith(DYNAMIC_PREFIX):
                classification = "github_dynamic_workflow"
            elif path in present:
                classification = "present_repository_workflow"
            elif state == "active" and path in reserved:
                classification = "active_pr_reserved"
            elif state == "active":
                classification = "active_orphan"
            else:
                classification = "disabled_absent"
            records.append(
                {
                    "workflow_id": workflow_id,
                    "path": path,
                    "state": state,
                    "classification": classification,
                    "default_branch_sha": observed_sha,
                    "observed_at": observed_at,
                    "registry_page": expected_page_number,
                }
            )

    if expected_total is None or item_count != expected_total:
        raise AuditError("workflow registry pagination is incomplete")
    records.sort(key=lambda record: (int(record["workflow_id"]), str(record["path"])))
    return {
        "format": "egressweave.workflow-registry-audit.v1",
        "repository_default_sha": observed_sha,
        "observed_at": observed_at,
        "records": records,
        "receipts": receipts,
    }


def _api_url(repository: str, suffix: str, **query: object) -> str:
    """Build one validated GitHub REST URL without embedding credentials."""
    repository = _require_repository(repository)
    encoded_query = urllib.parse.urlencode(query)
    base = f"{API_ROOT}/repos/{repository}/{suffix.lstrip('/')}"
    return f"{base}?{encoded_query}" if encoded_query else base


def _collect_open_pr_workflow_paths(repository: str, token: str | None) -> set[str]:
    """Collect current workflow paths still owned by bounded open pull requests."""
    reserved: set[str] = set()
    for pr_page in range(1, DEFAULT_MAX_PR_PAGES + 1):
        pulls = request_json(
            _api_url(repository, "pulls", state="open", per_page=100, page=pr_page),
            token=token,
        )
        if not isinstance(pulls, list):
            raise AuditError("pull request pagination is malformed")
        for pull in pulls:
            if not isinstance(pull, Mapping):
                raise AuditError("pull request record is malformed")
            number = pull.get("number")
            if isinstance(number, bool) or not isinstance(number, int) or number <= 0:
                raise AuditError("pull request number is invalid")
            exhausted_files = False
            for file_page in range(1, DEFAULT_MAX_PR_FILE_PAGES + 1):
                files = request_json(
                    _api_url(
                        repository,
                        f"pulls/{number}/files",
                        per_page=100,
                        page=file_page,
                    ),
                    token=token,
                )
                if not isinstance(files, list):
                    raise AuditError("pull request file pagination is malformed")
                for changed_file in files:
                    if not isinstance(changed_file, Mapping):
                        raise AuditError("pull request file record is malformed")
                    filename = changed_file.get("filename")
                    status = changed_file.get("status")
                    if (
                        isinstance(filename, str)
                        and status != "removed"
                        and filename.startswith(WORKFLOW_PREFIX)
                    ):
                        reserved.add(_require_workflow_path(filename))
                if len(files) < 100:
                    exhausted_files = True
                    break
            if not exhausted_files:
                raise AuditError("pull request file pagination exceeded the safety bound")
        if len(pulls) < 100:
            return reserved
    raise AuditError("pull request pagination exceeded the safety bound")


def audit_repository(
    repository: str,
    expected_default_sha: str,
    *,
    token: str | None = None,
    observed_at: str | None = None,
) -> dict[str, object]:
    """Build one live read-only audit bound to an expected protected revision."""
    repository = _require_repository(repository)
    expected_sha = _require_sha(expected_default_sha, label="expected default branch")
    repository_data = request_json(_api_url(repository, ""), token=token)
    if not isinstance(repository_data, Mapping):
        raise AuditError("repository metadata is malformed")
    default_branch = repository_data.get("default_branch")
    if not isinstance(default_branch, str) or not default_branch:
        raise AuditError("repository default branch is invalid")
    encoded_branch = urllib.parse.quote(default_branch, safe="")
    initial_branch = request_json(
        _api_url(repository, f"branches/{encoded_branch}"),
        token=token,
    )
    if not isinstance(initial_branch, Mapping):
        raise AuditError("default branch metadata is malformed")
    initial_commit = initial_branch.get("commit")
    if not isinstance(initial_commit, Mapping):
        raise AuditError("default branch commit metadata is malformed")
    initial_sha = _require_sha(initial_commit.get("sha"), label="observed default branch")
    if initial_sha != expected_sha:
        raise AuditError("default branch moved before workflow registry audit")

    contents = request_json(
        _api_url(repository, "contents/.github/workflows", ref=expected_sha),
        token=token,
    )
    if not isinstance(contents, list):
        raise AuditError("workflow source listing is malformed")
    present_paths: set[str] = set()
    for item in contents:
        if not isinstance(item, Mapping):
            raise AuditError("workflow source entry is malformed")
        path = item.get("path")
        item_type = item.get("type")
        if item_type == "file":
            present_paths.add(_require_workflow_path(path))

    registry_pages = collect_registry_pages(
        lambda page: request_json(
            _api_url(repository, "actions/workflows", per_page=100, page=page),
            token=token,
        )
    )
    active_pr_paths = _collect_open_pr_workflow_paths(repository, token)

    final_branch = request_json(
        _api_url(repository, f"branches/{encoded_branch}"),
        token=token,
    )
    if not isinstance(final_branch, Mapping):
        raise AuditError("default branch metadata is malformed")
    final_commit = final_branch.get("commit")
    if not isinstance(final_commit, Mapping):
        raise AuditError("default branch commit metadata is malformed")
    final_sha = _require_sha(final_commit.get("sha"), label="observed default branch")
    timestamp = observed_at or datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z"
    )
    return build_audit(
        registry_pages=registry_pages,
        present_paths=present_paths,
        active_pr_paths=active_pr_paths,
        expected_default_sha=expected_sha,
        observed_default_sha=final_sha,
        observed_at=timestamp,
    )


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    """Parse the bounded operator interface for the read-only detector."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", required=True, help="GitHub repository as owner/name")
    parser.add_argument(
        "--expected-default-sha",
        required=True,
        help="Exact protected default-branch SHA to which the audit must remain bound",
    )
    parser.add_argument(
        "--token-env",
        default="GITHUB_TOKEN",
        help="Environment variable containing an optional read-only GitHub token",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    """Emit deterministic JSON and return nonzero while active orphans remain."""
    args = _parse_args(argv)
    token = os.environ.get(args.token_env) if args.token_env else None
    try:
        audit = audit_repository(
            args.repository,
            args.expected_default_sha,
            token=token,
        )
    except AuditError as exc:
        print(f"workflow registry audit failed: {exc}", file=sys.stderr)
        return 3
    print(json.dumps(audit, sort_keys=True, separators=(",", ":")))
    records = audit.get("records")
    if isinstance(records, list) and any(
        isinstance(record, Mapping) and record.get("classification") == "active_orphan"
        for record in records
    ):
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())