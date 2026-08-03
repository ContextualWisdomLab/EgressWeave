"""Fail-closed boundary checks for EgressWeave's autonomous product workflow."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import tempfile
from collections.abc import Iterable, Sequence
from pathlib import Path, PurePosixPath

ALLOWED_ROOTS = ("src/egressweave/", "tests/", "docs/")
ALLOWED_FILES = frozenset({"README.md", "CHANGELOG.md"})
SAFE_PATH = re.compile(r"[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*")
MAX_FILES = 10
MAX_FILE_BYTES = 524_288
MAX_TOTAL_BYTES = 2_000_000
MAX_PATCH_BYTES = 2_000_000
MAX_CHANGED_LINES = 1_000
DIFF_SAFETY = ("--no-ext-diff", "--no-textconv", "--no-renames")


class BoundaryError(RuntimeError):
    """Raised when an autonomous patch crosses a fail-closed boundary."""


def _run(
    args: Sequence[str],
    *,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
    text: bool = False,
    check: bool = True,
) -> subprocess.CompletedProcess[str] | subprocess.CompletedProcess[bytes]:
    """Run one trusted local command without invoking a shell."""

    return subprocess.run(
        list(args),
        cwd=cwd,
        env=env,
        check=check,
        capture_output=True,
        text=text,
    )


def _git_command(
    *,
    git_dir: Path | None = None,
    work_tree: Path | None = None,
) -> list[str]:
    """Build a literal-pathspec Git command for a selected repository view."""

    command = ["git", "--literal-pathspecs"]
    if git_dir is not None:
        command.append(f"--git-dir={git_dir}")
    if work_tree is not None:
        command.append(f"--work-tree={work_tree}")
    return command


def _nul_names(
    git: Sequence[str],
    args: Sequence[str],
    *,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
) -> list[str]:
    """Return strict UTF-8 filenames from a NUL-delimited Git response."""

    raw = _run([*git, *args, "-z"], cwd=cwd, env=env).stdout
    assert isinstance(raw, bytes)
    return [part.decode("utf-8", errors="strict") for part in raw.split(b"\0") if part]


def _path_allowed(path: str) -> bool:
    """Return whether a repository-relative path is inside the product boundary."""

    pure = PurePosixPath(path)
    return (
        SAFE_PATH.fullmatch(path) is not None
        and not pure.is_absolute()
        and all(part not in {"", ".", ".."} for part in pure.parts)
        and (path in ALLOWED_FILES or path.startswith(ALLOWED_ROOTS))
    )


def _changed_paths(
    git: Sequence[str],
    *,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
) -> tuple[list[str], list[str]]:
    """Return changed and deleted paths from a repository view."""

    names = _nul_names(
        git,
        ["diff", *DIFF_SAFETY, "--name-only", "--diff-filter=ACMRTUXB"],
        cwd=cwd,
        env=env,
    )
    deleted = _nul_names(
        git,
        ["diff", *DIFF_SAFETY, "--name-only", "--diff-filter=D"],
        cwd=cwd,
        env=env,
    )
    return names, deleted


def validate_worktree_diff(
    *,
    workspace: Path,
    git: Sequence[str],
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
) -> list[str]:
    """Validate a materialized diff and return its bounded changed paths."""

    names, deleted = _changed_paths(git, cwd=cwd, env=env)
    if deleted:
        raise BoundaryError(f"Autonomous maintenance must not delete files: {deleted}")
    if not names:
        raise BoundaryError("A dirty tree contained no reviewable text changes")
    if len(names) > MAX_FILES:
        raise BoundaryError(f"Autonomous maintenance touched too many files: {len(names)}")

    total_bytes = 0
    for name in names:
        if not _path_allowed(name):
            raise BoundaryError(f"Autonomous maintenance crossed its path boundary: {name!r}")
        path = workspace / name
        file_stat = path.lstat()
        if not stat.S_ISREG(file_stat.st_mode):
            raise BoundaryError(f"Autonomous maintenance created a non-regular file: {name}")
        if file_stat.st_nlink != 1:
            raise BoundaryError(f"Autonomous maintenance created a hard link: {name}")
        if file_stat.st_mode & 0o111:
            raise BoundaryError(f"Autonomous maintenance created an executable file: {name}")
        if file_stat.st_size > MAX_FILE_BYTES:
            raise BoundaryError(f"Autonomous maintenance exceeded the per-file limit: {name}")
        total_bytes += file_stat.st_size
        if b"\x00" in path.read_bytes():
            raise BoundaryError(f"Autonomous maintenance created a binary file: {name}")
    if total_bytes > MAX_TOTAL_BYTES:
        raise BoundaryError("Autonomous maintenance exceeded the changed-file byte limit")

    summary = _run([*git, "diff", *DIFF_SAFETY, "--summary"], cwd=cwd, env=env, text=True)
    assert isinstance(summary.stdout, str)
    if " mode change " in summary.stdout:
        raise BoundaryError("Autonomous maintenance must not change file modes")

    numstat = _run([*git, "diff", *DIFF_SAFETY, "--numstat", "-z"], cwd=cwd, env=env).stdout
    assert isinstance(numstat, bytes)
    changed_lines = 0
    for record in (part for part in numstat.split(b"\0") if part):
        additions, deletions, _ = record.split(b"\t", 2)
        if additions == b"-" or deletions == b"-":
            raise BoundaryError("Autonomous maintenance produced a binary diff")
        changed_lines += int(additions) + int(deletions)
    if changed_lines > MAX_CHANGED_LINES:
        raise BoundaryError(
            f"Autonomous maintenance exceeded the changed-line budget: {changed_lines}"
        )

    _run([*git, "diff", "--no-ext-diff", "--no-textconv", "--check"], cwd=cwd, env=env)
    return names


def validate_patch_text(patch_file: Path) -> list[str]:
    """Validate diff metadata before Git writes any untrusted patch content."""

    if patch_file.stat().st_size > MAX_PATCH_BYTES:
        raise BoundaryError("Patch exceeded the byte limit")
    patch = patch_file.read_text(encoding="utf-8")
    headers = re.findall(r"^diff --git a/([^\n]+) b/([^\n]+)$", patch, re.MULTILINE)
    if not headers:
        raise BoundaryError("Patch has no reviewable diff headers")
    if len(headers) > MAX_FILES:
        raise BoundaryError(f"Patch touched too many files: {len(headers)}")

    seen: set[str] = set()
    for left, right in headers:
        if left != right or not _path_allowed(left) or left in seen:
            raise BoundaryError(f"Patch contains an unsafe or duplicate path: {left!r}, {right!r}")
        seen.add(left)

    for marker, path in re.findall(r"^(---|\+\+\+) (.+)$", patch, re.MULTILINE):
        if path == "/dev/null":
            continue
        prefix = "a/" if marker == "---" else "b/"
        if not path.startswith(prefix) or path[2:] not in seen:
            raise BoundaryError(f"Patch contains an unsafe file marker: {marker} {path}")

    forbidden = (
        "deleted file mode ",
        "old mode ",
        "new mode ",
        "rename from ",
        "rename to ",
        "copy from ",
        "copy to ",
        "GIT binary patch",
        "Binary files ",
        "new file mode 120000",
    )
    if any(token in patch for token in forbidden):
        raise BoundaryError(
            "Patch contains a forbidden deletion, rename, mode, link, or binary directive"
        )
    new_modes = re.findall(r"^new file mode ([0-7]{6})$", patch, re.MULTILINE)
    if any(mode != "100644" for mode in new_modes):
        raise BoundaryError(f"Patch contains a forbidden new-file mode: {new_modes}")
    return sorted(seen)


def _write_outputs(values: dict[str, str]) -> None:
    """Append simple key-value outputs to the current GitHub Actions step."""

    output = os.environ.get("GITHUB_OUTPUT")
    if not output:
        return
    with Path(output).open("a", encoding="utf-8") as stream:
        stream.writelines(f"{key}={value}\n" for key, value in values.items())


def _prepare_diff_index(
    *,
    git: Sequence[str],
    head: str,
    index_file: Path,
) -> dict[str, str]:
    """Create an alternate index that exposes safe untracked files to Git diff."""

    env = os.environ.copy()
    env["GIT_INDEX_FILE"] = str(index_file)
    _run([*git, "read-tree", head], env=env)
    untracked = _run([*git, "ls-files", "--others", "--exclude-standard", "-z"], env=env).stdout
    assert isinstance(untracked, bytes)
    if untracked:
        pathspec = index_file.with_suffix(".pathspec")
        pathspec.write_bytes(untracked)
        _run(
            [
                *git,
                "add",
                "-N",
                f"--pathspec-from-file={pathspec}",
                "--pathspec-file-nul",
            ],
            env=env,
        )
    return env


def capture(args: argparse.Namespace) -> int:
    """Capture a bounded patch against a protected immutable baseline."""

    workspace = args.workspace.resolve()
    baseline_git = args.baseline.resolve() / ".git"
    expected_head = args.base_sha_file.read_text(encoding="utf-8").strip()
    baseline_head = _run(
        ["git", f"--git-dir={baseline_git}", "rev-parse", "HEAD"], text=True
    ).stdout.strip()
    if baseline_head != expected_head:
        raise BoundaryError("The immutable diff baseline changed during model execution")

    index_file = args.patch_file.with_suffix(".index")
    git = _git_command(git_dir=baseline_git, work_tree=workspace)
    env = _prepare_diff_index(
        git=git,
        head=expected_head,
        index_file=index_file,
    )

    quiet = _run(
        [*git, "diff", "--no-ext-diff", "--no-textconv", "--quiet"],
        env=env,
        check=False,
    )
    if quiet.returncode == 0:
        _write_outputs({"changed": "false", "base_sha": expected_head})
        return 0
    if quiet.returncode != 1:
        raise BoundaryError("Git could not determine whether the model changed the workspace")

    validate_worktree_diff(workspace=workspace, git=git, env=env)
    patch = _run([*git, "diff", *DIFF_SAFETY, "--binary"], env=env).stdout
    stat_text = _run([*git, "diff", *DIFF_SAFETY, "--stat"], env=env, text=True).stdout
    assert isinstance(patch, bytes)
    assert isinstance(stat_text, str)
    if len(patch) > MAX_PATCH_BYTES:
        raise BoundaryError("Autonomous maintenance exceeded the patch byte limit")
    args.patch_file.write_bytes(patch)
    args.stat_file.write_text(stat_text, encoding="utf-8")
    _write_outputs({"changed": "true", "base_sha": expected_head})
    return 0


def apply_patch(args: argparse.Namespace) -> int:
    """Validate and materialize a patch on a fresh protected checkout."""

    workspace = args.workspace.resolve()
    patch_file = args.patch_file.resolve()
    validate_patch_text(patch_file)
    _run(["git", "apply", "--check", str(patch_file)], cwd=workspace)
    _run(["git", "apply", str(patch_file)], cwd=workspace)
    base_sha = _run(["git", "rev-parse", "HEAD"], cwd=workspace, text=True).stdout.strip()
    git = _git_command(git_dir=workspace / ".git", work_tree=workspace)
    env = _prepare_diff_index(
        git=git,
        head=base_sha,
        index_file=args.result_file.with_suffix(".index"),
    )
    validate_worktree_diff(workspace=workspace, git=git, env=env)
    digest = hashlib.sha256(patch_file.read_bytes()).hexdigest()
    result = {"base_sha": base_sha, "patch_sha256": digest}
    args.result_file.write_text(json.dumps(result, sort_keys=True) + "\n", encoding="utf-8")
    return 0


def self_test() -> int:
    """Exercise safe capture and fail-closed patch metadata rejection."""

    with tempfile.TemporaryDirectory() as root_text:
        root = Path(root_text)
        workspace = root / "workspace"
        baseline = root / "baseline"
        workspace.mkdir()
        _run(["git", "init", "-q"], cwd=workspace)
        _run(["git", "config", "user.name", "Guard Test"], cwd=workspace)
        _run(["git", "config", "user.email", "guard@example.invalid"], cwd=workspace)
        (workspace / "README.md").write_text("before\n", encoding="utf-8")
        (workspace / "src/egressweave").mkdir(parents=True)
        (workspace / "src/egressweave/__init__.py").write_text(
            "\"\"\"Package.\"\"\"\n", encoding="utf-8"
        )
        _run(["git", "add", "."], cwd=workspace)
        _run(["git", "commit", "-qm", "base"], cwd=workspace)
        _run(["git", "clone", "-q", "--local", "--no-hardlinks", str(workspace), str(baseline)])
        base_sha = _run(["git", "rev-parse", "HEAD"], cwd=workspace, text=True).stdout.strip()
        base_file = root / "base-sha"
        base_file.write_text(base_sha + "\n", encoding="utf-8")
        (workspace / "README.md").write_text("after\n", encoding="utf-8")
        patch_file = root / "change.patch"
        stat_file = root / "change.stat"
        capture(
            argparse.Namespace(
                workspace=workspace,
                baseline=baseline,
                base_sha_file=base_file,
                patch_file=patch_file,
                stat_file=stat_file,
            )
        )
        validate_patch_text(patch_file)
        unsafe = root / "unsafe.patch"
        unsafe.write_text(
            "diff --git a/pyproject.toml b/pyproject.toml\n"
            "--- a/pyproject.toml\n+++ b/pyproject.toml\n@@ -1 +1 @@\n-a\n+b\n",
            encoding="utf-8",
        )
        try:
            validate_patch_text(unsafe)
        except BoundaryError:
            pass
        else:
            raise AssertionError("Unsafe build-configuration patch was accepted")
    print("hourly product guard self-test passed")
    return 0


def build_parser() -> argparse.ArgumentParser:
    """Build the command-line parser for trusted workflow callers."""

    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    capture_parser = subparsers.add_parser("capture", help="capture a bounded workspace diff")
    capture_parser.add_argument("--workspace", type=Path, required=True)
    capture_parser.add_argument("--baseline", type=Path, required=True)
    capture_parser.add_argument("--base-sha-file", type=Path, required=True)
    capture_parser.add_argument("--patch-file", type=Path, required=True)
    capture_parser.add_argument("--stat-file", type=Path, required=True)
    capture_parser.set_defaults(handler=capture)

    apply_parser = subparsers.add_parser("apply", help="validate and apply a bounded patch")
    apply_parser.add_argument("--workspace", type=Path, required=True)
    apply_parser.add_argument("--patch-file", type=Path, required=True)
    apply_parser.add_argument("--result-file", type=Path, required=True)
    apply_parser.set_defaults(handler=apply_patch)

    self_test_parser = subparsers.add_parser("self-test", help="run focused guard regression tests")
    self_test_parser.set_defaults(handler=lambda _args: self_test())
    return parser


def main(argv: Iterable[str] | None = None) -> int:
    """Run the requested fail-closed guard operation."""

    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)
    try:
        return int(args.handler(args))
    except (BoundaryError, OSError, subprocess.CalledProcessError, UnicodeError, ValueError) as exc:
        parser.exit(1, f"hourly product guard rejected the change: {exc}\n")


if __name__ == "__main__":
    raise SystemExit(main())
