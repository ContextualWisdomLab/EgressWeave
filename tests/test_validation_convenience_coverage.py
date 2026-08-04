"""Coverage for the synchronous normalized-URL convenience wrapper."""

from egressweave import EgressPolicy, validate_egress_url


def test_validate_egress_url_returns_none_for_absent_configuration() -> None:
    """Preserve the documented empty-input result without invoking DNS."""
    policy = EgressPolicy.from_hosts("api.example.com")

    assert validate_egress_url(None, policy=policy) is None
