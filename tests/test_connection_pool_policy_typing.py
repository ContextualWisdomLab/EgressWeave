"""Static public-contract tests for connection-pool policy configuration."""

from __future__ import annotations

from typing import get_type_hints

from egressweave import EgressConnectionPoolPolicy


def test_connection_count_annotations_accept_documented_ascii_decimal_text() -> None:
    """Keep type-checker guidance aligned with the supported runtime contract."""
    annotations = get_type_hints(EgressConnectionPoolPolicy)

    assert annotations["max_connections"] == int | str
    assert annotations["max_keepalive_connections"] == int | str
