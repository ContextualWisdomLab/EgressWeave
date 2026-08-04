"""Repository contract for exact-current-head pull-request validation.

GitHub's default ``pull_request`` checkout points at a synthetic merge commit.
EgressWeave additionally requires every quality and package-acceptance job to
bind its checkout to the immutable pull-request head SHA so a green result can
be attributed to the exact revision reviewed by maintainers and automation.
"""

from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
CI_WORKFLOW_PATH = REPOSITORY_ROOT / ".github" / "workflows" / "ci.yml"


def test_pull_request_jobs_checkout_and_verify_the_exact_current_head() -> None:
    """Require both CI jobs to execute only the event's immutable source SHA."""
    workflow = CI_WORKFLOW_PATH.read_text(encoding="utf-8")

    assert "CI_SOURCE_SHA: ${{ github.event.pull_request.head.sha || github.sha }}" in workflow
    assert workflow.count("ref: ${{ env.CI_SOURCE_SHA }}") == 2
    assert workflow.count("EXPECTED_SOURCE_SHA: ${{ env.CI_SOURCE_SHA }}") == 2
    assert workflow.count('test "$(git rev-parse HEAD)" = "$EXPECTED_SOURCE_SHA"') == 2
