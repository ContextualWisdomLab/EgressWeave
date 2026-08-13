"""Expose exact owned-production line and function-body coverage metrics.

Coverage.py remains the source of statement and branch truth. This helper reads
its JSON output, verifies that every owned Python source file is represented,
and adds a conservative function-body view: a function counts as covered only
when every measured executable line in its body executed. The helper adds no
runtime dependency and exits non-zero whenever the evidence is incomplete or
anything measurable falls below 100%.
"""

from __future__ import annotations

import argparse
import ast
import json
import sys
from pathlib import Path
from typing import Any

_MAX_COVERAGE_JSON_BYTES = 16 * 1024 * 1024


class CoverageEvidenceError(ValueError):
    """Describe malformed or incomplete coverage evidence that cannot be trusted."""


def _parse_args() -> argparse.Namespace:
    """Parse the two explicit filesystem inputs used by hosted CI."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--coverage-json", required=True, type=Path)
    parser.add_argument("--source-root", required=True, type=Path)
    return parser.parse_args()


def _load_json(path: Path) -> dict[str, Any]:
    """Load one bounded regular JSON file and require an object at the root."""
    resolved = path.resolve(strict=True)
    if not resolved.is_file():
        raise CoverageEvidenceError("coverage JSON must be a regular file")
    if resolved.stat().st_size > _MAX_COVERAGE_JSON_BYTES:
        raise CoverageEvidenceError("coverage JSON exceeds the 16 MiB evidence limit")
    try:
        payload = json.loads(resolved.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise CoverageEvidenceError("coverage JSON is unreadable or malformed") from exc
    if type(payload) is not dict:
        raise CoverageEvidenceError("coverage JSON root must be an object")
    return payload


def _line_set(value: object, *, field: str) -> set[int]:
    """Validate a coverage.py line-number list without accepting bool subclasses."""
    if type(value) is not list:
        raise CoverageEvidenceError(f"{field} must be a list")
    lines: set[int] = set()
    for item in value:
        if type(item) is not int or item <= 0:
            raise CoverageEvidenceError(f"{field} must contain positive exact integers")
        if item in lines:
            raise CoverageEvidenceError(f"{field} contains a duplicate line number")
        lines.add(item)
    return lines


def _is_within(path: Path, root: Path) -> bool:
    """Return whether one resolved path is contained by the resolved source root."""
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _owned_coverage_records(
    payload: dict[str, Any],
    *,
    source_root: Path,
) -> dict[Path, dict[str, Any]]:
    """Map every owned source path to its unique coverage.py file record."""
    files = payload.get("files")
    if type(files) is not dict:
        raise CoverageEvidenceError("coverage JSON files must be an object")

    records: dict[Path, dict[str, Any]] = {}
    for raw_path, raw_record in files.items():
        if type(raw_path) is not str or type(raw_record) is not dict:
            raise CoverageEvidenceError("coverage file records must map strings to objects")
        candidate = Path(raw_path)
        if not candidate.is_absolute():
            candidate = Path.cwd() / candidate
        resolved = candidate.resolve(strict=False)
        if not _is_within(resolved, source_root):
            continue
        if resolved in records:
            raise CoverageEvidenceError("coverage JSON aliases one owned source file twice")
        records[resolved] = raw_record

    owned_files: set[Path] = set()
    for path in source_root.rglob("*.py"):
        relative = path.relative_to(source_root)
        if path.is_symlink():
            raise CoverageEvidenceError(
                f"owned source tree contains a symbolic link: {relative}"
            )
        if not path.is_file():
            continue
        resolved = path.resolve(strict=True)
        if not _is_within(resolved, source_root):
            raise CoverageEvidenceError(
                f"owned source path escapes source root: {relative}"
            )
        if resolved in owned_files:
            raise CoverageEvidenceError(
                "owned source tree aliases one Python source file twice"
            )
        owned_files.add(resolved)
    if not owned_files:
        raise CoverageEvidenceError("source root contains no owned Python source files")

    missing = sorted(owned_files - records.keys())
    if missing:
        relative = ", ".join(str(path.relative_to(source_root)) for path in missing[:20])
        suffix = "" if len(missing) <= 20 else f" (+{len(missing) - 20} more)"
        raise CoverageEvidenceError(
            f"coverage data missing owned source files: {relative}{suffix}"
        )

    unexpected = sorted(records.keys() - owned_files)
    if unexpected:
        relative = ", ".join(str(path.relative_to(source_root)) for path in unexpected[:20])
        suffix = "" if len(unexpected) <= 20 else f" (+{len(unexpected) - 20} more)"
        raise CoverageEvidenceError(
            f"coverage data references absent owned source files: {relative}{suffix}"
        )
    return records


def _function_body_lines(node: ast.FunctionDef | ast.AsyncFunctionDef) -> tuple[int, int]:
    """Return the inclusive source span containing a function's executable body."""
    if not node.body:
        raise CoverageEvidenceError(f"function {node.name!r} has no syntax body")
    start = node.body[0].lineno
    end = node.end_lineno
    if end is None:
        raise CoverageEvidenceError(f"function {node.name!r} has no end-line metadata")
    return start, end


def _nested_function_body_lines(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> set[int]:
    """Return body lines owned by nested functions rather than their enclosing one."""
    nested_lines: set[int] = set()
    for child in ast.walk(node):
        if child is node or not isinstance(
            child,
            (ast.FunctionDef, ast.AsyncFunctionDef),
        ):
            continue
        start, end = _function_body_lines(child)
        nested_lines.update(
            line for line in range(start, end + 1) if line > child.lineno
        )
    return nested_lines


def _analyse_source(
    path: Path,
    record: dict[str, Any],
    *,
    source_root: Path,
) -> tuple[int, int, int, int, list[str]]:
    """Return covered/total line and measurable-function counts for one source file."""
    executed = _line_set(record.get("executed_lines"), field="executed_lines")
    missing = _line_set(record.get("missing_lines"), field="missing_lines")
    overlap = executed & missing
    if overlap:
        raise CoverageEvidenceError("executed_lines and missing_lines overlap")
    measured = executed | missing
    if not measured:
        raise CoverageEvidenceError(
            f"owned source file has no measured executable lines: {path.relative_to(source_root)}"
        )

    try:
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(path))
    except (OSError, UnicodeError, SyntaxError) as exc:
        raise CoverageEvidenceError(
            f"owned source file is unreadable or syntactically invalid: {path.relative_to(source_root)}"
        ) from exc

    source_line_count = len(source.splitlines())
    if any(line > source_line_count for line in measured):
        raise CoverageEvidenceError(
            "coverage data line number exceeds owned source file: "
            f"{path.relative_to(source_root)}"
        )

    function_total = 0
    function_covered = 0
    uncovered: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        start, end = _function_body_lines(node)
        nested_body_lines = _nested_function_body_lines(node)
        measured_body = {
            line
            for line in measured
            if start <= line <= end
            and line > node.lineno
            and line not in nested_body_lines
        }
        if not measured_body:
            continue
        function_total += 1
        if measured_body <= executed:
            function_covered += 1
        else:
            uncovered.append(f"{path.relative_to(source_root)}:{node.name}")

    return len(executed), len(measured), function_covered, function_total, uncovered


def _percentage(covered: int, total: int) -> float:
    """Return a percentage while refusing an empty denominator."""
    if total <= 0:
        raise CoverageEvidenceError("coverage metric denominator must be positive")
    return 100.0 * covered / total


def main() -> int:
    """Validate evidence, print exact metrics, and fail below complete coverage."""
    args = _parse_args()
    try:
        source_root = args.source_root.resolve(strict=True)
        if not source_root.is_dir():
            raise CoverageEvidenceError("source root must be a directory")
        payload = _load_json(args.coverage_json)
        records = _owned_coverage_records(payload, source_root=source_root)

        line_covered = 0
        line_total = 0
        function_covered = 0
        function_total = 0
        uncovered_functions: list[str] = []
        for path in sorted(records):
            metrics = _analyse_source(path, records[path], source_root=source_root)
            line_covered += metrics[0]
            line_total += metrics[1]
            function_covered += metrics[2]
            function_total += metrics[3]
            uncovered_functions.extend(metrics[4])

        line_percentage = _percentage(line_covered, line_total)
        function_percentage = _percentage(function_covered, function_total)
    except (OSError, CoverageEvidenceError) as exc:
        print(f"coverage-evidence-error: {exc}", file=sys.stderr)
        return 2

    print(
        "coverage-metrics: "
        f"line={line_percentage:.2f}% ({line_covered}/{line_total}) "
        f"function={function_percentage:.2f}% ({function_covered}/{function_total})"
    )
    if line_covered != line_total or function_covered != function_total:
        if uncovered_functions:
            preview = ", ".join(uncovered_functions[:20])
            suffix = "" if len(uncovered_functions) <= 20 else (
                f" (+{len(uncovered_functions) - 20} more)"
            )
            print(f"uncovered function bodies: {preview}{suffix}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
