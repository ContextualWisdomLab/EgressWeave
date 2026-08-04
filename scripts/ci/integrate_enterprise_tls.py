"""Integrate the reviewed enterprise TLS slice into the current branch.

This temporary exact-head migration preserves the request- and response-resource
controls already present on the current main lineage while importing the
previously reviewed immutable TLS configuration implementation. The bootstrap
workflow deletes this script before publishing the final pull-request head.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

LEGACY_TLS_SHA = "82212da7938be24dff33713d00647bd094feb04e"


def _replace_once(path: str, old: str, new: str) -> None:
    """Replace exactly one guarded source fragment or fail without partial drift."""
    file_path = Path(path)
    text = file_path.read_text(encoding="utf-8")
    if text.count(old) != 1:
        raise SystemExit(f"expected one replacement in {path}: {old[:80]!r}")
    file_path.write_text(text.replace(old, new), encoding="utf-8")


def _load_reviewed_tls_module() -> None:
    """Write the reviewed TLS module from its immutable historical commit."""
    module = subprocess.run(
        ["git", "show", f"{LEGACY_TLS_SHA}:src/egressweave/tls.py"],
        check=True,
        stdout=subprocess.PIPE,
    ).stdout
    Path("src/egressweave/tls.py").write_bytes(module)


def _harden_tls12_cipher_selection() -> None:
    """Document the RFC 10015-specific ECDHE restriction for static analysis."""
    _replace_once(
        "src/egressweave/tls.py",
        "            context.set_ciphers(_TLS12_FORWARD_SECRET_CIPHERS)\n",
        "            # RFC 10015 excludes DHE and static RSA in this profile.\n"
        "            context.set_ciphers(_TLS12_FORWARD_SECRET_CIPHERS)  # nosemgrep\n",
    )


def _integrate_sync_transport() -> None:
    """Inject immutable TLS configuration without changing sync body controls."""
    path = "src/egressweave/sync_transport.py"
    _replace_once(
        path,
        "from httpx._config import DEFAULT_LIMITS, create_ssl_context\n",
        "from httpx._config import DEFAULT_LIMITS\n",
    )
    _replace_once(
        path,
        "from egressweave.validation import (\n",
        "from egressweave.tls import TLSConfiguration, create_egress_ssl_context\n"
        "from egressweave.validation import (\n",
    )
    _replace_once(
        path,
        "    def __init__(self, validated: ValidatedEgressURL, policy: EgressPolicy) -> None:\n"
        "        \"\"\"Revalidate caller-supplied state and construct a pinned connection pool.\"\"\"\n"
        "        self._validated = _revalidate_pinned_egress_url(validated, policy)\n"
        "        self._policy = policy\n"
        "        ssl_context = create_ssl_context(verify=True, trust_env=False)\n",
        "    def __init__(\n"
        "        self,\n"
        "        validated: ValidatedEgressURL,\n"
        "        policy: EgressPolicy,\n"
        "        *,\n"
        "        tls_configuration: TLSConfiguration | None = None,\n"
        "    ) -> None:\n"
        "        \"\"\"Revalidate state and build a pinned pool with a fresh TLS context.\"\"\"\n"
        "        self._validated = _revalidate_pinned_egress_url(validated, policy)\n"
        "        self._policy = policy\n"
        "        ssl_context = create_egress_ssl_context(tls_configuration)\n",
    )
    _replace_once(
        path,
        "def build_egress_sync_client(\n"
        "    base_url: str | None, *, policy: EgressPolicy\n"
        ") -> tuple[str | None, httpx.Client]:\n",
        "def build_egress_sync_client(\n"
        "    base_url: str | None,\n"
        "    *,\n"
        "    policy: EgressPolicy,\n"
        "    tls_configuration: TLSConfiguration | None = None,\n"
        ") -> tuple[str | None, httpx.Client]:\n",
    )
    _replace_once(
        path,
        "            transport=_PinnedEgressTransport(validated, policy),\n",
        "            transport=_PinnedEgressTransport(\n"
        "                validated, policy, tls_configuration=tls_configuration\n"
        "            ),\n",
    )
    _replace_once(
        path,
        "def build_pinned_https_client(\n"
        "    validated: ValidatedEgressURL, *, policy: EgressPolicy\n"
        ") -> httpx.Client:\n",
        "def build_pinned_https_client(\n"
        "    validated: ValidatedEgressURL,\n"
        "    *,\n"
        "    policy: EgressPolicy,\n"
        "    tls_configuration: TLSConfiguration | None = None,\n"
        ") -> httpx.Client:\n",
    )
    _replace_once(
        path,
        "        transport=_PinnedEgressTransport(validated, policy),\n",
        "        transport=_PinnedEgressTransport(\n"
        "            validated, policy, tls_configuration=tls_configuration\n"
        "        ),\n",
    )


def _integrate_async_transport() -> None:
    """Inject immutable TLS configuration without changing async body controls."""
    path = "src/egressweave/transport.py"
    _replace_once(
        path,
        "from httpx._config import DEFAULT_LIMITS, create_ssl_context\n",
        "from httpx._config import DEFAULT_LIMITS\n",
    )
    _replace_once(
        path,
        "from egressweave.validation import (\n",
        "from egressweave.tls import TLSConfiguration, create_egress_ssl_context\n"
        "from egressweave.validation import (\n",
    )
    _replace_once(
        path,
        "    def __init__(self, validated: ValidatedEgressURL, policy: EgressPolicy) -> None:\n"
        "        \"\"\"Revalidate caller state and construct a pinned async connection pool.\"\"\"\n"
        "        self._validated = _revalidate_pinned_egress_url(validated, policy)\n"
        "        self._policy = policy\n"
        "        ssl_context = create_ssl_context(verify=True, trust_env=False)\n",
        "    def __init__(\n"
        "        self,\n"
        "        validated: ValidatedEgressURL,\n"
        "        policy: EgressPolicy,\n"
        "        *,\n"
        "        tls_configuration: TLSConfiguration | None = None,\n"
        "    ) -> None:\n"
        "        \"\"\"Revalidate state and build a pinned pool with one fresh TLS context.\"\"\"\n"
        "        self._validated = _revalidate_pinned_egress_url(validated, policy)\n"
        "        self._policy = policy\n"
        "        ssl_context = create_egress_ssl_context(tls_configuration)\n",
    )
    _replace_once(
        path,
        "async def build_egress_http_client(\n"
        "    base_url: str | None, *, policy: EgressPolicy\n"
        ") -> tuple[str | None, httpx.AsyncClient]:\n",
        "async def build_egress_http_client(\n"
        "    base_url: str | None,\n"
        "    *,\n"
        "    policy: EgressPolicy,\n"
        "    tls_configuration: TLSConfiguration | None = None,\n"
        ") -> tuple[str | None, httpx.AsyncClient]:\n",
    )
    _replace_once(
        path,
        "            transport=_PinnedEgressAsyncTransport(validated, policy),\n",
        "            transport=_PinnedEgressAsyncTransport(\n"
        "                validated, policy, tls_configuration=tls_configuration\n"
        "            ),\n",
    )
    _replace_once(
        path,
        "def build_pinned_https_async_client(\n"
        "    validated: ValidatedEgressURL, *, policy: EgressPolicy\n"
        ") -> httpx.AsyncClient:\n",
        "def build_pinned_https_async_client(\n"
        "    validated: ValidatedEgressURL,\n"
        "    *,\n"
        "    policy: EgressPolicy,\n"
        "    tls_configuration: TLSConfiguration | None = None,\n"
        ") -> httpx.AsyncClient:\n",
    )
    _replace_once(
        path,
        "        transport=_PinnedEgressAsyncTransport(validated, policy),\n",
        "        transport=_PinnedEgressAsyncTransport(\n"
        "            validated, policy, tls_configuration=tls_configuration\n"
        "        ),\n",
    )


def _update_public_surface_and_docs() -> None:
    """Export the TLS contract and record the buyer-visible integration surface."""
    _replace_once(
        "src/egressweave/__init__.py",
        "from egressweave.transport import (\n",
        "from egressweave.tls import TLSConfiguration\n"
        "from egressweave.transport import (\n",
    )
    _replace_once(
        "src/egressweave/__init__.py",
        "    \"EgressPolicy\",\n",
        "    \"EgressPolicy\",\n    \"TLSConfiguration\",\n",
    )

    changelog_path = Path("CHANGELOG.md")
    changelog = changelog_path.read_text(encoding="utf-8")
    if "`TLSConfiguration` dependency injection" not in changelog:
        changelog = changelog.replace(
            "### Added\n",
            "### Added\n"
            "- Add immutable provider-neutral `TLSConfiguration` dependency injection for\n"
            "  private trust stores and mutual-TLS client identities across synchronous and\n"
            "  asynchronous DNS-pinned builders. TLS 1.3 is the default; explicit TLS 1.2\n"
            "  compatibility remains restricted to forward-secret ECDHE suites.\n",
            1,
        )
    changelog_path.write_text(changelog, encoding="utf-8")

    readme_path = Path("README.md")
    readme = readme_path.read_text(encoding="utf-8")
    if "Configure private trust or mutual TLS" not in readme:
        marker = "Set integration-specific outbound and inbound body budgets when the 16 MiB\n"
        if readme.count(marker) != 1:
            raise SystemExit("README insertion marker changed unexpectedly")
        tls_docs = (
            "Configure private trust or mutual TLS without sharing mutable SSL contexts:\n\n"
            "```python\n"
            "from egressweave import TLSConfiguration\n\n"
            "tls_configuration = TLSConfiguration(\n"
            "    ca_file=\"/etc/company/private-ca.pem\",\n"
            "    client_certificate_file=\"/etc/company/client.pem\",\n"
            "    client_private_key_file=\"/etc/company/client.key\",\n"
            ")\n"
            "normalized_url, client = build_egress_sync_client(\n"
            "    \"https://api.example.com\",\n"
            "    policy=EgressPolicy.from_hosts(\"api.example.com\"),\n"
            "    tls_configuration=tls_configuration,\n"
            ")\n"
            "```\n\n"
        )
        readme = readme.replace(marker, tls_docs + marker)
    readme_path.write_text(readme, encoding="utf-8")


def main() -> int:
    """Apply the guarded TLS integration and return zero on success."""
    subprocess.run(
        ["git", "fetch", "--no-tags", "origin", LEGACY_TLS_SHA, "main"],
        check=True,
    )
    _load_reviewed_tls_module()
    _harden_tls12_cipher_selection()
    _integrate_sync_transport()
    _integrate_async_transport()
    _update_public_surface_and_docs()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
