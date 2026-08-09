# Version-stable special-purpose address classification

EgressWeave supports more than one CPython minor line. Security policy must therefore not silently widen or narrow merely because a deployment uses a different patch release whose `ipaddress` module carries older special-purpose registry tables. Remote-address validation applies a small **reviewed compatibility overlay** to the parsed address value before consulting the running interpreter's version-sensitive classification properties.

This overlay is deliberately narrow. It freezes only reviewed differences that matter to EgressWeave's fail-closed remote-egress decision; it is not a private replacement for the IANA registries, and there is **no runtime registry download** or other network dependency in address validation. New or changed assignments require a normal source change, test-first evidence, current primary-source review, and the complete repository gate set.

## Policy boundary

The compatibility layer preserves the current reviewed Python 3.13+ classification for ranges whose behavior changed across otherwise supported interpreter patch lines. The current bounded set includes:

| Address or range | EgressWeave remote decision | Current evidence |
|---|---|---|
| `192.0.0.0/24` | deny, except the two explicit globally reachable anycast addresses below | IANA IPv4 Special-Purpose Address Space and current CPython `ipaddress` |
| `192.0.0.9/32` | allow when every other EgressWeave authority check succeeds | IANA globally reachable exception |
| `192.0.0.10/32` | allow when every other EgressWeave authority check succeeds | IANA globally reachable exception |
| `64:ff9b:1::/48` | deny | IANA IPv6 Special-Purpose Address Space and current CPython `ipaddress` |
| `100:0:0:1::/64` | deny | IANA IPv6 Special-Purpose Address Space |
| `2001::/23` | deny except the reviewed globally reachable subranges below | IANA IPv6 Special-Purpose Address Space and current CPython `ipaddress` |
| `2001:1::1/128`, `2001:1::2/128`, `2001:1::3/128` | allow when every other EgressWeave authority check succeeds | IANA globally reachable exceptions; `2001:1::3/128` is included explicitly because the live registry is newer than the exception list currently described in Python documentation |
| `2001:3::/32`, `2001:4:112::/48`, `2001:20::/28`, `2001:30::/28` | allow when every other EgressWeave authority check succeeds | IANA globally reachable exceptions |
| `2001:2::/48` | deny | IANA IPv6 Special-Purpose Address Space |
| `2002::/16` | deny as the reviewed EgressWeave/CPython compatibility policy | Python 3.13+ classifies 6to4 as private; the current IANA registry's `Globally Reachable` is `N/A`, so this row must not be described as an IANA `False` value |
| `3fff::/20` | deny | IANA documentation prefix, not globally reachable |
| `5f00::/16` | deny | IANA segment-routing SIDs prefix, not globally reachable |

The broad-network rule is evaluated after explicit globally reachable exceptions, so an exception cannot be swallowed by its parent `192.0.0.0/24` or `2001::/23` compatibility range. Outside the reviewed overlay, EgressWeave continues to apply the running interpreter's `is_private`, `is_loopback`, `is_link_local`, `is_reserved`, `is_unspecified`, `is_multicast`, and `is_global` properties as defense in depth.

`2002::/16` is intentionally called out because registry and library vocabularies are not perfectly interchangeable. IANA currently records its `Globally Reachable` field as `N/A`; Python 3.14.6 documents that Python 3.13 changed `2002::/16` to `is_private=True`. EgressWeave adopts that reviewed CPython fail-closed behavior for consistent supported-runtime decisions, without claiming that IANA marks the range globally reachable `False`.

## Local-development boundary

The compatibility overlay does not grant local authority. `allow_local=True` still requires the exact allowlisted local hostname and port and retains the existing loopback/private-container restrictions. IP-literal URLs remain forbidden. An address made globally acceptable by an explicit compatibility exception still has to pass every ordinary hostname, port, method, DNS-pinning, transport, TLS, request, and resource policy check.

## Update procedure

A future registry or CPython change is a security-policy change, not a data refresh. Maintainers must:

1. compare the live IANA IPv4 and IPv6 special-purpose registries with the supported Python documentation and relevant CPython change;
2. add deterministic RED coverage that simulates the older interpreter property values while asserting the intended EgressWeave decision from the parsed address itself;
3. add the smallest explicit range or exception required, with broader parent ranges evaluated only after specific global exceptions;
4. update this note and the release-facing changelog without overclaiming IANA semantics; and
5. run the complete supported-Python matrix, 100% production statement/branch coverage, package acceptance, security scans, exact-head automated review, independent approval where required, and repository protections.

A mutable registry fetch at request time would make the security boundary non-reproducible and could change destination authority without a repository diff, so it remains out of scope.

## References

Internet Assigned Numbers Authority. (2025, October 9). *IANA IPv4 Special-Purpose Address Space*. https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xhtml

Internet Assigned Numbers Authority. (2025, October 9). *IANA IPv6 Special-Purpose Address Space*. https://www.iana.org/assignments/iana-ipv6-special-registry/iana-ipv6-special-registry.xhtml

Python Software Foundation. (2026). *ipaddress — IPv4/IPv6 manipulation library* (Python 3.14.6 documentation). https://docs.python.org/3.14/library/ipaddress.html

Stasiak, J. (2024, March 22). *GH-113171: Fix “private” (non-global) IP address ranges* [Commit `40d75c2`]. CPython. https://github.com/python/cpython/commit/40d75c2b7f5c67e254d0a025e0f2e2c7ada7f69f
