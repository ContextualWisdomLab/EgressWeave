"""Contracts for the gateway-backed OpenCode autonomous development scheduler."""

from __future__ import annotations

from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
PRODUCT_WORKFLOW_PATH = (
    REPOSITORY_ROOT / ".github" / "workflows" / "hourly-product-development.yml"
)
MAINTAINER_PROMPT_PATH = (
    REPOSITORY_ROOT / ".github" / "prompts" / "hourly-product-maintainer.md"
)
MAINTENANCE_DOCUMENTATION_PATH = (
    REPOSITORY_ROOT / "docs" / "hourly-autonomous-maintenance.md"
)
README_PATH = REPOSITORY_ROOT / "README.md"
OPENCODE_VERSION = "1.18.13"
OPENCODE_LINUX_X64_SHA256 = (
    "8d500b20fed2d26e537e221895b1a575476571b4f0089bb29fb13eeb8eb9e937"
)
GATEWAY_MODEL = "contextual-orchestrator/orchestrator/free"
GATEWAY_PROVIDER_SECRETS = (
    "BYTEZ_API_KEY",
    "NVIDIA_NIM_API_KEY",
    "NVIDIA_NIM_API_KEY_SUB",
    "OPENROUTER_API_KEY",
    "OPENAI_API_KEY",
)
TRUSTED_GATEWAY_SOURCE_SHA = "6958918beaad96d0a67ce264706c828bb7f3f000"


def _read(path: Path) -> str:
    """Return one repository text file as UTF-8."""
    return path.read_text(encoding="utf-8")


def test_product_scheduler_uses_pinned_opencode_through_the_governed_gateway() -> None:
    """Replace the Codex scheduler model step without mutable agent tooling."""
    workflow = _read(PRODUCT_WORKFLOW_PATH)

    assert "openai/codex-action@" not in workflow
    assert "codex run" not in workflow
    for secret_name in GATEWAY_PROVIDER_SECRETS:
        assert f"{secret_name}: ${{{{ secrets.{secret_name} }}}}" in workflow
    assert f'OPENCODE_VERSION: "{OPENCODE_VERSION}"' in workflow
    assert f'OPENCODE_SHA256: "{OPENCODE_LINUX_X64_SHA256}"' in workflow
    assert (
        "https://github.com/anomalyco/opencode/releases/download/"
        "v${OPENCODE_VERSION}/opencode-linux-x64.tar.gz"
    ) in workflow
    assert "sha256sum --check" in workflow
    assert "opencode run --auto" in workflow
    assert f'OPENCODE_MODEL: "{GATEWAY_MODEL}"' in workflow
    assert f'"model":"{GATEWAY_MODEL}"' in workflow
    assert f'"small_model":"{GATEWAY_MODEL}"' in workflow


def test_gateway_sidecar_is_vendored_at_a_pinned_immutable_commit() -> None:
    """Fetch the reviewed org sidecar by exact SHA, never a floating ref."""
    workflow = _read(PRODUCT_WORKFLOW_PATH)

    assert f'TRUSTED_GATEWAY_SOURCE_SHA: "{TRUSTED_GATEWAY_SOURCE_SHA}"' in workflow
    assert (
        "git clone --quiet https://github.com/ContextualWisdomLab/.github.git"
        in workflow
    )
    assert (
        'git -C "$source_dir" -c advice.detachedHead=false checkout --quiet '
        '"$TRUSTED_GATEWAY_SOURCE_SHA"'
    ) in workflow
    assert 'checked_out="$(git -C "$source_dir" rev-parse HEAD)"' in workflow
    assert '[ "$checked_out" != "$TRUSTED_GATEWAY_SOURCE_SHA" ]' in workflow
    assert (
        'bash "${TRUSTED_GATEWAY_SOURCE}/scripts/ci/contextual_orchestrator_review_sidecar.sh"'
        in workflow
    )
    assert (
        'source "${TRUSTED_GATEWAY_SOURCE}/scripts/ci/load_contextual_orchestrator_token.sh"'
        in workflow
    )
    # Vendored outside $GITHUB_WORKSPACE: the sidecar's own checkout must never
    # land inside the git repository the patch-capture guard diffs against the
    # pristine baseline.
    assert 'source_dir="${RUNNER_TEMP}/trusted-gateway-source"' in workflow
    assert 'echo "TRUSTED_GATEWAY_SOURCE=$source_dir" >>"$GITHUB_ENV"' in workflow


def test_model_execution_keeps_a_fail_closed_permission_and_secret_boundary() -> None:
    """Deny unneeded tools and reject model output containing a credential."""
    workflow = _read(PRODUCT_WORKFLOW_PATH)

    # Runner-network egress is audit-mode, matching the only production
    # precedent for this exact sidecar anywhere in the org (ContextualWisdomLab
    # /.github's pr-review-autofix.yml and strix.yml); the sidecar's live
    # multi-provider discovery has no fixed host set for a block-mode
    # allowlist to pin. See the "Harden runner" step's own comment.
    assert "egress-policy: audit" in workflow
    assert "egress-policy: block" not in workflow
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
    assert 'grep -R -F -l -- "$value"' in workflow
    assert 'grep -R -F -- "$value"' not in workflow
    assert "CONTEXTUAL_ORCHESTRATOR_TOKEN" in workflow


def test_credentialed_model_runner_never_executes_model_modified_code() -> None:
    """Keep untrusted repository execution in the offline secret-free verifier."""
    workflow = _read(PRODUCT_WORKFLOW_PATH)
    maintainer_prompt = _read(MAINTAINER_PROMPT_PATH)
    documentation = " ".join(_read(MAINTENANCE_DOCUMENTATION_PATH).split())

    assert '"pytest *":"allow"' not in workflow
    assert '"python -m compileall *":"allow"' not in workflow
    assert '"lsp":"allow"' not in workflow
    assert "Do not execute repository code in this credential-bearing step" in maintainer_prompt
    assert "does not execute model-modified repository code" in documentation


def test_open_pull_request_gates_count_every_paginated_page() -> None:
    """Refuse development or reverification for an open PR beyond page one."""
    workflow = " ".join(
        _read(PRODUCT_WORKFLOW_PATH).replace("\\\n", "").split()
    )
    complete_query = (
        'gh api "repos/${GITHUB_REPOSITORY}/pulls?state=open&per_page=100" '
        "--paginate --jq 'length' | "
        "awk '{total += $1} END {print total + 0}'"
    )

    assert workflow.count(complete_query) == 2
    assert "--slurp" not in workflow


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
    initial_handoff = workflow.split(
        "Upload the bounded change for credential-free reverification", 1
    )[1].split("\n\n  reverify:", 1)[0]
    assert "${{ runner.temp }}/base-sha" in initial_handoff
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


def test_operator_documentation_records_the_pinned_agent_and_gateway_mapping() -> None:
    """Make the autonomous execution supply chain understandable to operators."""
    documentation = _read(MAINTENANCE_DOCUMENTATION_PATH)

    assert f"OpenCode {OPENCODE_VERSION}" in documentation
    for secret_name in GATEWAY_PROVIDER_SECRETS:
        assert f"`{secret_name}`" in documentation
    assert f"`{GATEWAY_MODEL}`" in documentation
    assert "`CONTEXTUAL_ORCHESTRATOR_TOKEN`" in documentation
    assert OPENCODE_LINUX_X64_SHA256 in documentation
    assert TRUSTED_GATEWAY_SOURCE_SHA in documentation
    assert "OpenAI Codex Action" not in documentation


def test_operator_documentation_forbids_repository_local_patch_publication() -> None:
    """Document that verified patches require an external promotion boundary."""
    documentation = " ".join(_read(MAINTENANCE_DOCUMENTATION_PATH).split())

    assert "does not create a branch, pull request, or auto-merge request" in documentation
    assert "external credential-separated promotion mechanism" in documentation
    assert "reconstruct and verify the exact tree" in documentation


def test_buyer_readme_identifies_the_opencode_gateway_maintainer() -> None:
    """Keep the public execution identity aligned with the audited workflow."""
    readme = _read(README_PATH)

    assert "bounded Codex maintainer" not in readme
    assert "bounded OpenCode maintainer" in readme
    assert "contextual-orchestrator gateway" in readme
    assert "`NVIDIA_NIM_API_KEY`" in readme
    assert "COPILOT_GITHUB_TOKEN" not in readme


def test_product_workflow_keeps_printf_escapes_on_indented_yaml_lines() -> None:
    """Keep shell format escapes on one YAML line so workflow parsing succeeds."""
    workflow = _read(PRODUCT_WORKFLOW_PATH)
    workflow_lines = workflow.splitlines()
    checksum_line = (
        "          printf '%s  %s\\n' "
        '"$OPENCODE_SHA256" "$archive" | sha256sum --check -'
    )
    fallback_line = (
        "            printf '%s\\n' "
        "'{\"type\":\"error\",\"message\":\"OpenCode produced no final result\"}' "
        '>"$result_file"'
    )

    assert checksum_line in workflow_lines
    assert fallback_line in workflow_lines
    assert workflow.endswith("\n")


def test_offline_verifier_materializes_the_complete_repository_contract() -> None:
    """Make every repository-owned test input available before offline checks run."""
    workflow = _read(PRODUCT_WORKFLOW_PATH)
    verifier = workflow.split(
        "Test only inside the offline least-privilege verifier container",
        1,
    )[1].split("Recheck the independently verified immutable patch", 1)[0]

    for required_directory in (
        "/source/src",
        "/source/tests",
        "/source/docs",
        "/source/.github",
        "/source/scripts",
    ):
        assert required_directory in verifier

    root_loop = "for root_file in /source/* /source/.[!.]* /source/..?*; do"
    regular_file_guard = (
        '[ -f "$root_file" ] && [ ! -L "$root_file" ] || continue'
    )
    root_copy = (
        'cp --no-preserve=ownership,mode,timestamps "$root_file" /work/'
    )
    compileall = "python -m compileall -q src tests scripts"
    assert root_loop in verifier
    assert regular_file_guard in verifier
    assert root_copy in verifier
    assert compileall in verifier
    assert verifier.index(root_loop) < verifier.index("ruff check .")
    assert verifier.index(root_copy) < verifier.index("pytest -q")
    assert verifier.index(root_copy) < verifier.index(compileall)


def test_gateway_evidence_directory_is_excluded_from_the_captured_patch() -> None:
    """Keep the sidecar's own strix_runs/ evidence out of the model's diff."""
    gitignore = _read(REPOSITORY_ROOT / ".gitignore")

    assert "strix_runs/" in gitignore
