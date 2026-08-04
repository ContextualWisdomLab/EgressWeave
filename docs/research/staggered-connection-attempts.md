# Staggered pinned connection attempts

## Decision

The asynchronous pinned transport starts one validated address immediately and
starts each later candidate only after a 250 ms delay while earlier attempts are
still pending. The first successful stream wins; every losing task is cancelled
and awaited. A later candidate receives only the connection-timeout budget that
remains, so staggered racing does not multiply the caller's timeout.

## Standards basis

RFC 8305 section 5 states that connection attempts should not all begin
simultaneously because doing so creates unreasonable network load. It recommends
starting one address first, adding later attempts one at a time, cancelling all
losers after the first success, and using 250 ms as the default Connection
Attempt Delay. The RFC also sets a 10 ms absolute lower bound and recommends a
100 ms practical minimum for implementations that make the delay configurable.

EgressWeave uses the RFC's 250 ms default internally. Immediate failure may
advance the next validated candidate without waiting for an idle delay, because
there is no longer a concurrent attempt to protect and avoiding unnecessary
latency preserves the failover purpose of Happy Eyeballs.

## Threat and reliability model

A hostname can legitimately resolve to several IPv4 and IPv6 addresses. The
previous transport created one task for every validated address at once. That
closed the DNS-rebinding gap, but a large or compromised DNS answer could cause
a burst of simultaneous TCP handshakes and local tasks. It also diverged from
the network-load guidance in RFC 8305.

The staggered scheduler preserves the original security invariants:

1. every address was returned by the bounded validation resolver;
2. every address is revalidated immediately before connect;
3. the hostname and port must still match the validated authority;
4. no unvalidated address can be introduced while racing;
5. the first successful stream is returned and every loser is cancelled and
   awaited; and
6. the caller's connection-timeout budget is shared across attempts.

The synchronous transport remains sequential and therefore does not create the
simultaneous-attempt burst addressed by this change.

## Primary references

- [RFC 8305 section 5: Connection Attempts](https://www.rfc-editor.org/rfc/rfc8305.html#section-5)
- [RFC 8305 section 8: Summary of Configurable Values](https://www.rfc-editor.org/rfc/rfc8305.html#section-8)
- [CWE-400: Uncontrolled Resource Consumption](https://cwe.mitre.org/data/definitions/400.html)
