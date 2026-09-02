from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PRODUCT_WORKFLOW_PATH = ROOT / ".github" / "workflows" / "hourly-product-development.yml"
REVIEW_WORKFLOW_PATH = ROOT / ".github" / "workflows" / "hourly-pr-maintenance.yml"
MAINTENANCE_DOCUMENTATION_PATH = ROOT / "docs" / "hourly-autonomous-maintenance.md"

OPENCODE_VERSION = "1.18.13"
OPENCODE_LINUX_X64_SHA256 = (
    "8d500b20fed2d26e537e221895b1a575476571b4f0089bb29fb13eeb8eb9e937"
)
NVIDIA_MODEL = "nvidia/nemotron-3-super-120b-a12b"


def _read(path: Path) -> str:
    """Read a repository contract as UTF-8 text."""
    return path.read_text(encoding="utf-8")


def _product_development_mapping_section(documentation: str) -> str:
    """Return the bounded operator section that binds OpenCode to NVIDIA NIM."""
    start = "### 1. Read-only development and patch capture"
    end = "### 2. Credential-free isolated reverification"
    assert start in documentation
    assert end in documentation
    return documentation.split(start, 1)[1].split(end, 1)[0]


def test_product_workflow_pins_the_reviewed_opencode_release() -> None:
    """Keep the model-execution CLI bound to one reviewed immutable release."""
    workflow = _read(PRODUCT_WORKFLOW_PATH)

    assert f'OPENCODE_VERSION: "{OPENCODE_VERSION}"' in workflow
    assert OPENCODE_LINUX_X64_SHA256 in workflow
    assert "https://github.com/anomalyco/opencode/releases/download/" in workflow
    assert "sha256sum --check" in workflow
    assert (
        "curl --proto '=https' --tlsv1.2 --fail --location --silent --show-error"
        in workflow
    )
    assert "curl | sh" not in workflow


def test_product_workflow_uses_the_exact_nvidia_model_and_secret_mapping() -> None:
    """Keep the model and provider credential contract explicit and auditable."""
    workflow = _read(PRODUCT_WORKFLOW_PATH)

    assert NVIDIA_MODEL in workflow
    assert "NVIDIA_NIM_API_KEY: ${{ secrets.NVIDIA_NIM_API_KEY }}" in workflow
    assert "NVIDIA_API_KEY: ${{ secrets.NVIDIA_NIM_API_KEY }}" in workflow
    assert "OPENAI_API_KEY" not in workflow
    assert "ANTHROPIC_API_KEY" not in workflow


def test_product_workflow_does_not_give_the_model_repository_write_identity() -> None:
    """Keep autonomous model execution unable to publish repository state."""
    workflow = _read(PRODUCT_WORKFLOW_PATH)

    assert "contents: read" in workflow
    assert "contents: write" not in workflow
    assert "pull-requests: write" not in workflow
    assert "id-token: write" not in workflow
    assert "persist-credentials: false" in workflow
    assert "git push" not in workflow
    assert "gh pr create" not in workflow
    assert "enable-auto-merge" not in workflow


def test_product_workflow_keeps_model_execution_on_a_bounded_patch_surface() -> None:
    """Require the repository-reviewed patch guard around autonomous edits."""
    workflow = _read(PRODUCT_WORKFLOW_PATH)

    assert "scripts/ci/hourly_product_guard.py" in workflow
    assert "capture" in workflow
    assert "reverify" in workflow
    assert "MAX_CHANGED_FILES" in workflow
    assert "MAX_CHANGED_LINES" in workflow


def test_product_workflow_reverification_is_credential_free() -> None:
    """Keep model-generated code execution out of the credential-bearing job."""
    workflow = _read(PRODUCT_WORKFLOW_PATH)

    develop_start = workflow.index("  develop:")
    verify_start = workflow.index("  reverify:")
    develop = workflow[develop_start:verify_start]
    reverify = workflow[verify_start:]

    assert "NVIDIA_NIM_API_KEY" in develop
    assert "NVIDIA_NIM_API_KEY" not in reverify
    assert "permissions:\n      contents: read" in reverify
    assert "id-token: write" not in reverify
    assert "network: none" in reverify
    assert "cap-drop ALL" in reverify
    assert "no-new-privileges" in reverify


def test_product_workflow_does_not_execute_model_modified_code_with_secret() -> None:
    """Keep source/test execution deferred until after the model secret is gone."""
    workflow = _read(PRODUCT_WORKFLOW_PATH)

    develop_start = workflow.index("  develop:")
    verify_start = workflow.index("  reverify:")
    develop = workflow[develop_start:verify_start]

    forbidden = (
        "pytest",
        "ruff",
        "compileall",
        "python -m",
        "python3 -m",
    )
    assert all(command not in develop for command in forbidden)


def test_pr_maintenance_uses_only_named_review_credentials() -> None:
    """Keep reusable review jobs from inheriting unrelated repository secrets."""
    review_workflow = _read(REVIEW_WORKFLOW_PATH)

    assert "secrets: inherit" not in review_workflow
    assert review_workflow.count(
        "PR_REVIEW_MERGE_TOKEN: ${{ secrets.PR_REVIEW_MERGE_TOKEN }}"
    ) == 2
    assert review_workflow.count(
        "OPENCODE_APPROVE_TOKEN: ${{ secrets.OPENCODE_APPROVE_TOKEN }}"
    ) == 2


def test_operator_documentation_records_the_pinned_agent_and_secret_mapping() -> None:
    """Make the autonomous execution supply chain understandable to operators."""
    documentation = _read(MAINTENANCE_DOCUMENTATION_PATH)
    mapping = _product_development_mapping_section(documentation)

    assert f"OpenCode {OPENCODE_VERSION}" in mapping
    assert "`NVIDIA_NIM_API_KEY`" in mapping
    assert "`NVIDIA_API_KEY`" in mapping
    assert NVIDIA_MODEL in mapping
    assert OPENCODE_LINUX_X64_SHA256 in mapping
    assert "OpenAI Codex Action" not in documentation


def test_operator_documentation_forbids_repository_local_patch_publication() -> None:
    """Document that verified patches require an external promotion boundary."""
    documentation = " ".join(_read(MAINTENANCE_DOCUMENTATION_PATH).split())

    assert "does not create a branch, pull request, or auto-merge request" in documentation
    assert "external credential-separated promotion mechanism" in documentation
    assert "reconstruct and verify the exact tree" in documentation


def test_operator_documentation_identifies_the_opencode_nvidia_maintainer() -> None:
    """Keep audited maintainer identity in the operator surface, not buyer copy."""
    documentation = _read(MAINTENANCE_DOCUMENTATION_PATH)
    mapping = _product_development_mapping_section(documentation)

    assert "bounded Codex maintainer" not in documentation
    assert f"OpenCode {OPENCODE_VERSION}" in mapping
    assert NVIDIA_MODEL in mapping
    assert "`NVIDIA_NIM_API_KEY`" in mapping
    assert "COPILOT_GITHUB_TOKEN" not in documentation


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
