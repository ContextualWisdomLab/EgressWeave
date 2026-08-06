"""Contracts for the NVIDIA-backed OpenCode autonomous development scheduler."""

from __future__ import annotations

from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
PRODUCT_WORKFLOW_PATH = (
    REPOSITORY_ROOT / ".github" / "workflows" / "hourly-product-development.yml"
)
REVIEW_WORKFLOW_PATH = (
    REPOSITORY_ROOT / ".github" / "workflows" / "hourly-pr-maintenance.yml"
)
MAINTENANCE_DOCUMENTATION_PATH = (
    REPOSITORY_ROOT / "docs" / "hourly-autonomous-maintenance.md"
)
README_PATH = REPOSITORY_ROOT / "README.md"
OPENCODE_VERSION = "1.18.13"
OPENCODE_LINUX_X64_SHA256 = (
    "8d500b20fed2d26e537e221895b1a575476571b4f0089bb29fb13eeb8eb9e937"
)
NVIDIA_MODEL = "nvidia/nemotron-3-super-120b-a12b"
NVIDIA_API_HOST_LABELS = ("integrate", "api", "nvidia", "com")
NVIDIA_API_ENDPOINT = f"{'.'.join(NVIDIA_API_HOST_LABELS)}:443"


def _read(path: Path) -> str:
    """Return one repository text file as UTF-8."""
    return path.read_text(encoding="utf-8")


def test_product_scheduler_uses_pinned_opencode_with_nvidia_nim() -> None:
    """Replace the Codex scheduler model step without mutable agent tooling."""
    workflow = _read(PRODUCT_WORKFLOW_PATH)

    assert "openai/codex-action@" not in workflow
    assert "OPENAI_API_KEY" not in workflow
    assert "NVIDIA_API_KEY: ${{ secrets.NVIDIA_NIM_API_KEY }}" in workflow
    assert f'OPENCODE_VERSION: "{OPENCODE_VERSION}"' in workflow
    assert f'OPENCODE_SHA256: "{OPENCODE_LINUX_X64_SHA256}"' in workflow
    assert (
        "https://github.com/anomalyco/opencode/releases/download/"
        "v${OPENCODE_VERSION}/opencode-linux-x64.tar.gz"
    ) in workflow
    assert "sha256sum --check" in workflow
    assert "opencode run --auto" in workflow
    assert f'OPENCODE_MODEL: "{NVIDIA_MODEL}"' in workflow


def test_model_execution_keeps_a_fail_closed_permission_and_secret_boundary() -> None:
    """Deny unneeded tools and reject model output containing its credential."""
    workflow = _read(PRODUCT_WORKFLOW_PATH)

    assert "egress-policy: block" in workflow
    assert NVIDIA_API_ENDPOINT in {line.strip() for line in workflow.splitlines()}
    assert 'OPENCODE_DISABLE_AUTOUPDATE: "true"' in workflow
    assert 'OPENCODE_DISABLE_MODELS_FETCH: "true"' in workflow
    assert 'OPENCODE_DISABLE_DEFAULT_PLUGINS: "true"' in workflow
    assert 'OPENCODE_DISABLE_LSP_DOWNLOAD: "true"' in workflow
    assert 'OPENCODE_DISABLE_PROJECT_CONFIG: "true"' in workflow
    assert 'HOME: "${{ runner.temp }}/opencode-home"' in workflow
    assert 'XDG_CONFIG_HOME: "${{ runner.temp }}/opencode-home/config"' in workflow
    assert '"external_directory":"deny"' in workflow
    assert '"webfetch":"deny"' in workflow
    assert '"websearch":"deny"' in workflow
    assert '"question":"deny"' in workflow
    assert '"task":"deny"' in workflow
    assert '"skill":"deny"' in workflow
    assert "Reject model credential disclosure" in workflow
    assert 'grep -R -F -l -- "$NVIDIA_API_KEY"' in workflow
    assert 'grep -R -F -- "$NVIDIA_API_KEY"' not in workflow


def test_credentialed_model_runner_never_executes_model_modified_code() -> None:
    """Keep untrusted repository execution in the offline secret-free verifier."""
    workflow = _read(PRODUCT_WORKFLOW_PATH)
    documentation = " ".join(_read(MAINTENANCE_DOCUMENTATION_PATH).split())

    assert '"pytest *":"allow"' not in workflow
    assert '"python -m compileall *":"allow"' not in workflow
    assert '"lsp":"allow"' not in workflow
    assert "Do not execute repository code in this credential-bearing step" in workflow
    assert "does not execute model-modified repository code" in documentation


def test_open_pull_request_gates_count_every_paginated_page() -> None:
    """Refuse development or reverification for an open PR beyond page one."""
    workflow = " ".join(
        _read(PRODUCT_WORKFLOW_PATH).replace("\\\n", "").split()
    )
    complete_query = (
        'gh api "repos/${GITHUB_REPOSITORY}/pulls?state=open&per_page=100" '
        "--paginate --slurp --jq 'map(length) | add // 0'"
    )

    assert workflow.count(complete_query) == 2
    assert "--jq 'length'" not in workflow


def test_product_scheduler_never_publishes_a_model_modified_tree() -> None:
    """End the scheduler at a digest-bound credential-free patch handoff."""
    workflow = _read(PRODUCT_WORKFLOW_PATH)
    forbidden_fragments = (
        "\n  publish:",
        "id-token: write",
        "PR_REVIEW_MERGE_TOKEN",
        "OPENCODE_APPROVE_TOKEN",
        "exchange_github_app_token",
        "git remote set-url",
        "git push ",
        "gh pr create",
        "gh pr merge",
        "contents: write",
    )

    assert all(fragment not in workflow for fragment in forbidden_fragments)
    assert ": write" not in workflow
    assert "Require the exact handoff base before applying the patch" in workflow
    assert 'handoff_base_sha="$(cat "$handoff_base_sha_file")"' in workflow
    assert '[ "$current_sha" != "$EXPECTED_BASE_SHA" ] ||' in workflow
    assert '[ "$handoff_base_sha" != "$EXPECTED_BASE_SHA" ]; then' in workflow
    assert "The patch handoff base does not match the exact checkout" in workflow
    assert 'result_base_sha="$(jq -r ".base_sha" "$result_file")"' in workflow
    assert '[ "$result_base_sha" != "$EXPECTED_BASE_SHA" ]; then' in workflow
    assert "Upload the independently verified handoff" in workflow
    recheck = workflow.split(
        "Recheck the independently verified immutable patch",
        1,
    )[1].split("Upload the independently verified handoff", 1)[0]
    assert "EXPECTED_BASE_SHA: ${{ needs.develop.outputs.base_sha }}" in recheck
    assert '[[ ! "$base_sha" =~ ^[0-9a-f]{40}$ ]]' in recheck
    assert '[ "$base_sha" != "$EXPECTED_BASE_SHA" ]' in recheck
    assert "does not match the exact handoff base" in recheck
    assert "hourly-verified-product-change-${{ github.run_id }}" in workflow
    assert "/opt/egressweave-reverify/egressweave.patch" in workflow
    assert "/opt/egressweave-reverify/base-sha" in workflow
    assert "/opt/egressweave-reverify/patch-sha256" in workflow
    handoff = workflow.split("Upload the independently verified handoff", 1)[1]
    assert "if-no-files-found: error" in handoff
    assert "retention-days: 3" in handoff


def test_review_scheduler_keeps_its_existing_identity_contract() -> None:
    """Do not repurpose the centrally managed review-agent credential path."""
    review_workflow = _read(REVIEW_WORKFLOW_PATH)

    assert "NVIDIA_NIM_API_KEY" not in review_workflow
    assert "OPENAI_API_KEY" not in review_workflow
    assert "pr-review-fix-scheduler.yml@" in review_workflow
    assert "pr-review-merge-scheduler.yml@" in review_workflow
    assert review_workflow.count("secrets: inherit") == 2


def test_operator_documentation_records_the_pinned_agent_and_secret_mapping() -> None:
    """Make the autonomous execution supply chain understandable to operators."""
    documentation = _read(MAINTENANCE_DOCUMENTATION_PATH)

    assert f"OpenCode {OPENCODE_VERSION}" in documentation
    assert "`NVIDIA_NIM_API_KEY`" in documentation
    assert "`NVIDIA_API_KEY`" in documentation
    assert NVIDIA_MODEL in documentation
    assert OPENCODE_LINUX_X64_SHA256 in documentation
    assert "OpenAI Codex Action" not in documentation


def test_operator_documentation_forbids_repository_local_patch_publication() -> None:
    """Document that verified patches require an external promotion boundary."""
    documentation = " ".join(_read(MAINTENANCE_DOCUMENTATION_PATH).split())

    assert "does not create a branch, pull request, or auto-merge request" in documentation
    assert "external credential-separated promotion mechanism" in documentation
    assert "reconstruct and verify the exact tree" in documentation


def test_buyer_readme_identifies_the_opencode_nvidia_maintainer() -> None:
    """Keep the public execution identity aligned with the audited workflow."""
    readme = _read(README_PATH)

    assert "bounded Codex maintainer" not in readme
    assert "bounded OpenCode maintainer" in readme
    assert "`NVIDIA_NIM_API_KEY`" in readme
    assert "COPILOT_GITHUB_TOKEN" not in readme


def test_buyer_readme_forbids_repository_local_patch_publication() -> None:
    """Keep buyer-facing workflow claims aligned with the read-only handoff."""
    readme = " ".join(_read(README_PATH).split())

    assert "A third publisher" not in readme
    assert "ends at the independently reverified credential-free patch handoff" in readme
    assert (
        "does not create branches, pull requests, repository writes, or auto-merge requests"
        in readme
    )
    assert "external, independently reviewed, credential-separated promotion" in readme
    assert "reconstruct and verify the exact tree before any repository write" in readme
