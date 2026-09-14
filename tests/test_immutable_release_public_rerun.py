"""Prove public immutable release reruns are verify-only and fail closed."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_REPOSITORY = "ContextualWisdomLab/EgressWeave"
_TAG = "v0.3.0"
_RELEASE_SHA = "a" * 40
_ASSETS = ("SHA256SUMS", "egressweave-0.3.0.whl", "egressweave-0.3.0.tar.gz")

_FAKE_GH = r'''
import json
import os
import sys
from pathlib import Path

state_path = Path(os.environ["FAKE_RELEASE_STATE"])
state = json.loads(state_path.read_text())
args = sys.argv[1:]
state["calls"].append(args)


def save():
    state_path.write_text(json.dumps(state))


def fail(message):
    save()
    print(message, file=sys.stderr)
    raise SystemExit(1)


if args[0] == "api":
    release_endpoint = (
        "repos/" + os.environ["GITHUB_REPOSITORY"] + "/releases/tags/" + os.environ["RELEASE_TAG"]
    )
    tag_endpoint = (
        "repos/" + os.environ["GITHUB_REPOSITORY"] + "/git/ref/tags/" + os.environ["RELEASE_TAG"]
    )
    if args[1] == release_endpoint:
        if not state["published"] and not state["created"]:
            fail("HTTP 404")
        print(
            json.dumps(
                {
                    "tag_name": os.environ["RELEASE_TAG"],
                    "draft": not state["published"],
                    "prerelease": False,
                    "immutable": state["published"],
                    "assets": [{"name": name} for name in state["remote_assets"]],
                }
            )
        )
    elif args[1] == tag_endpoint:
        print(json.dumps({"object": {"sha": state["tag_sha"]}}))
    else:
        fail("unexpected api endpoint")
elif args[0] == "release":
    if len(args) < 3 or args[2] != os.environ["RELEASE_TAG"]:
        fail("wrong release tag")
    if "--repo" not in args or args[args.index("--repo") + 1] != os.environ["GITHUB_REPOSITORY"]:
        fail("explicit repository selection required")
    if args[1] == "create":
        if state["published"]:
            fail("public release already exists")
        state["created"] = True
        first_option = next(
            (index for index, value in enumerate(args[3:], start=3) if value.startswith("--")),
            len(args),
        )
        state["remote_assets"] = [Path(value).name for value in args[3:first_option]]
    elif args[1] == "edit":
        if not state["created"]:
            fail("draft release does not exist")
        state["published"] = True
    elif args[1] == "verify":
        if not state["published"]:
            fail("release is not public")
        state["release_verified"] = True
    elif args[1] == "verify-asset":
        if not state["published"]:
            fail("release is not public")
        asset = Path(args[3]).name
        if asset not in state["remote_assets"]:
            fail("asset is not attached to release")
        state["verified_assets"].append(asset)
    else:
        fail("unexpected release command")
else:
    fail("unexpected command")

save()
'''


def _publication_script() -> str:
    """Return the repository-owned final publication shell, not a copied command list."""
    workflow = (_ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
    step = workflow.split("      - name: Create a complete draft and publish it atomically\n", 1)[1]
    script = step.split("        run: |\n", 1)[1]
    return "\n".join(line[10:] for line in script.splitlines() if line.startswith("          "))


def _run_public_rerun(tmp_path: Path, remote_assets: tuple[str, ...]) -> tuple[subprocess.CompletedProcess[str], dict]:
    state = {
        "calls": [],
        "created": False,
        "published": True,
        "release_verified": False,
        "remote_assets": list(remote_assets),
        "verified_assets": [],
        "tag_sha": _RELEASE_SHA,
    }
    state_path = tmp_path / "state.json"
    state_path.write_text(json.dumps(state), encoding="utf-8")

    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    gh = bin_dir / "gh"
    gh.write_text(f"#!{sys.executable} -S\n" + _FAKE_GH, encoding="utf-8")
    gh.chmod(0o700)

    evidence = tmp_path / "release-evidence"
    evidence.mkdir()
    for name in _ASSETS:
        (evidence / name).write_text("reviewed fixture\n", encoding="utf-8")

    env = dict(os.environ)
    env.update(
        {
            "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}",
            "FAKE_RELEASE_STATE": str(state_path),
            "GITHUB_REPOSITORY": _REPOSITORY,
            "RELEASE_SHA": _RELEASE_SHA,
            "RELEASE_TAG": _TAG,
        }
    )
    result = subprocess.run(
        ["bash", "-c", _publication_script()],
        cwd=tmp_path,
        env=env,
        text=True,
        capture_output=True,
        timeout=15,
        check=False,
    )
    return result, json.loads(state_path.read_text(encoding="utf-8"))


def test_existing_public_immutable_release_is_reverified_without_mutation(tmp_path: Path) -> None:
    """A failed completion check must be recoverable without recreating a public release."""
    result, state = _run_public_rerun(tmp_path, _ASSETS)
    assert result.returncode == 0, result.stderr + result.stdout
    release_subcommands = [call[1] for call in state["calls"] if call[:1] == ["release"]]
    assert "create" not in release_subcommands
    assert "edit" not in release_subcommands
    assert state["release_verified"]
    assert sorted(state["verified_assets"]) == sorted(_ASSETS)


def test_existing_public_release_with_wrong_asset_inventory_fails_closed(tmp_path: Path) -> None:
    """Verify-only recovery cannot bless a public release with missing reviewed evidence."""
    result, state = _run_public_rerun(tmp_path, _ASSETS[:-1])
    assert result.returncode != 0
    release_subcommands = [call[1] for call in state["calls"] if call[:1] == ["release"]]
    assert "create" not in release_subcommands
    assert "edit" not in release_subcommands
