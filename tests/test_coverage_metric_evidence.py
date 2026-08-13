"""Regression contract for explicit owned-production coverage evidence.

Statement/branch coverage remains the normative 100% gate. These tests add a
machine-readable human-visible line/function metric so reviewers can see what
the aggregate percentage represents instead of inferring it from a summary.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
REPORTER = REPOSITORY_ROOT / "scripts" / "ci" / "report_coverage_metrics.py"
CI_WORKFLOW = REPOSITORY_ROOT / ".github" / "workflows" / "ci.yml"


def _write_fixture(
    tmp_path: Path,
    *,
    executed_lines: list[int],
    missing_lines: list[int],
) -> tuple[Path, Path]:
    """Create one tiny owned source tree plus coverage.py-style JSON evidence."""
    source_root = tmp_path / "src" / "egressweave"
    source_root.mkdir(parents=True)
    source_file = source_root / "sample.py"
    source_file.write_text(
        "def choose(value: bool) -> int:\n"
        "    if value:\n"
        "        return 1\n"
        "    return 0\n"
        "\n\n"
        "async def answer() -> int:\n"
        "    return 42\n",
        encoding="utf-8",
    )
    coverage_json = tmp_path / "coverage.json"
    measured = len(executed_lines) + len(missing_lines)
    coverage_json.write_text(
        json.dumps(
            {
                "meta": {"branch_coverage": True, "version": "fixture"},
                "files": {
                    str(source_file): {
                        "executed_lines": executed_lines,
                        "missing_lines": missing_lines,
                        "excluded_lines": [],
                        "summary": {
                            "covered_lines": len(executed_lines),
                            "num_statements": measured,
                            "missing_lines": len(missing_lines),
                        },
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    return source_root, coverage_json


def _write_noop_fixture(tmp_path: Path) -> tuple[Path, Path]:
    """Create one measured function plus a docstring-only no-op function."""
    source_root = tmp_path / "src" / "egressweave"
    source_root.mkdir(parents=True)
    source_file = source_root / "sample.py"
    source_file.write_text(
        "def measured() -> int:\n"
        "    return 1\n"
        "\n\n"
        "def noop() -> None:\n"
        "    \"\"\"Intentionally has no measurable executable body.\"\"\"\n",
        encoding="utf-8",
    )
    coverage_json = tmp_path / "coverage.json"
    coverage_json.write_text(
        json.dumps(
            {
                "meta": {"branch_coverage": True, "version": "fixture"},
                "files": {
                    str(source_file): {
                        "executed_lines": [1, 2, 5],
                        "missing_lines": [],
                        "excluded_lines": [],
                        "summary": {
                            "covered_lines": 3,
                            "num_statements": 3,
                            "missing_lines": 0,
                        },
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    return source_root, coverage_json


def _write_nested_fixture(tmp_path: Path) -> tuple[Path, Path]:
    """Create a covered outer function whose uncalled nested function is missing."""
    source_root = tmp_path / "src" / "egressweave"
    source_root.mkdir(parents=True)
    source_file = source_root / "sample.py"
    source_file.write_text(
        "def outer() -> int:\n"
        "    def inner() -> int:\n"
        "        return 2\n"
        "    return 1\n",
        encoding="utf-8",
    )
    coverage_json = tmp_path / "coverage.json"
    coverage_json.write_text(
        json.dumps(
            {
                "meta": {"branch_coverage": True, "version": "fixture"},
                "files": {
                    str(source_file): {
                        "executed_lines": [1, 2, 4],
                        "missing_lines": [3],
                        "excluded_lines": [],
                        "summary": {
                            "covered_lines": 3,
                            "num_statements": 4,
                            "missing_lines": 1,
                        },
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    return source_root, coverage_json


def _write_single_line_nested_fixture(tmp_path: Path) -> tuple[Path, Path]:
    """Create a nested function whose definition and body share one trace line."""
    source_root = tmp_path / "src" / "egressweave"
    source_root.mkdir(parents=True)
    source_file = source_root / "sample.py"
    source_file.write_text(
        "def outer() -> int:\n"
        "    def inner() -> int: return 2\n"
        "    return 1\n",
        encoding="utf-8",
    )
    coverage_json = tmp_path / "coverage.json"
    coverage_json.write_text(
        json.dumps(
            {
                "meta": {"branch_coverage": True, "version": "fixture"},
                "files": {
                    str(source_file): {
                        "executed_lines": [1, 2, 3],
                        "missing_lines": [],
                        "excluded_lines": [],
                        "summary": {
                            "covered_lines": 3,
                            "num_statements": 3,
                            "missing_lines": 0,
                        },
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    return source_root, coverage_json


def _run_reporter(source_root: Path, coverage_json: Path) -> subprocess.CompletedProcess[str]:
    """Run the repository reporter exactly as CI will invoke it."""
    return subprocess.run(
        [
            sys.executable,
            str(REPORTER),
            "--coverage-json",
            str(coverage_json),
            "--source-root",
            str(source_root),
        ],
        cwd=REPOSITORY_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )


def test_reporter_exposes_exact_line_and_function_body_metrics(tmp_path: Path) -> None:
    """A fully covered source tree reports explicit 100% line/function evidence."""
    source_root, coverage_json = _write_fixture(
        tmp_path,
        executed_lines=[1, 2, 3, 4, 7, 8],
        missing_lines=[],
    )

    result = _run_reporter(source_root, coverage_json)

    assert result.returncode == 0, result.stderr
    assert "line=100.00% (6/6)" in result.stdout
    assert "function=100.00% (2/2)" in result.stdout


def test_reporter_excludes_functions_without_measurable_body_lines(tmp_path: Path) -> None:
    """Do not turn a docstring-only no-op into impossible function-coverage debt."""
    source_root, coverage_json = _write_noop_fixture(tmp_path)

    result = _run_reporter(source_root, coverage_json)

    assert result.returncode == 0, result.stderr
    assert "line=100.00% (3/3)" in result.stdout
    assert "function=100.00% (1/1)" in result.stdout
    assert "noop" not in result.stderr


def test_reporter_counts_nested_function_bodies_only_for_the_nested_function(
    tmp_path: Path,
) -> None:
    """An uncalled inner body must not make its fully covered outer body missing."""
    source_root, coverage_json = _write_nested_fixture(tmp_path)

    result = _run_reporter(source_root, coverage_json)

    assert result.returncode == 1
    assert "line=75.00% (3/4)" in result.stdout
    assert "function=50.00% (1/2)" in result.stdout
    assert "sample.py:inner" in result.stderr
    assert "sample.py:outer" not in result.stderr


def test_reporter_excludes_single_line_bodies_without_distinct_trace_evidence(
    tmp_path: Path,
) -> None:
    """Definition-line execution alone must not claim an uncalled body is covered."""
    source_root, coverage_json = _write_single_line_nested_fixture(tmp_path)

    result = _run_reporter(source_root, coverage_json)

    assert result.returncode == 0, result.stderr
    assert "line=100.00% (3/3)" in result.stdout
    assert "function=100.00% (1/1)" in result.stdout


def test_reporter_fails_closed_when_a_function_body_has_a_missing_line(
    tmp_path: Path,
) -> None:
    """A missing executable function-body line must make the evidence non-passing."""
    source_root, coverage_json = _write_fixture(
        tmp_path,
        executed_lines=[1, 2, 3, 7, 8],
        missing_lines=[4],
    )

    result = _run_reporter(source_root, coverage_json)

    assert result.returncode == 1
    assert "line=83.33% (5/6)" in result.stdout
    assert "function=50.00% (1/2)" in result.stdout
    assert "sample.py:choose" in result.stderr


def test_reporter_rejects_incomplete_owned_source_coverage(tmp_path: Path) -> None:
    """Every owned Python source file must be represented by coverage evidence."""
    source_root, coverage_json = _write_fixture(
        tmp_path,
        executed_lines=[1, 2, 3, 4, 7, 8],
        missing_lines=[],
    )
    (source_root / "unreported.py").write_text(
        "def hidden() -> int:\n    return 1\n",
        encoding="utf-8",
    )

    result = _run_reporter(source_root, coverage_json)

    assert result.returncode == 2
    assert "coverage data missing owned source files" in result.stderr
    assert "unreported.py" in result.stderr


def test_ci_exposes_the_exact_metrics_after_coverage_collection() -> None:
    """The hosted matrix must publish the reporter output on every exact head."""
    workflow = CI_WORKFLOW.read_text(encoding="utf-8")

    assert "coverage json -o coverage.json" in workflow
    assert (
        "python scripts/ci/report_coverage_metrics.py --coverage-json coverage.json "
        "--source-root src/egressweave"
    ) in workflow
