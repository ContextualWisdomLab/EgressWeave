"""Response resource limits shared by synchronous and asynchronous transports.

An allowlisted authority can still be attacker-controlled or compromised. Without
explicit consumption budgets, a valid outbound request can return an unbounded
field section or body and exhaust process memory, disk-backed buffers, or worker
capacity. EgressWeave bounds decoded response-header fields and their name/value
bytes, requests identity coding, rejects a body-bearing response that nevertheless
applies a content coding, rejects unsafe declared lengths before caller-visible
delivery, and counts every transfer-decoded body byte while it is consumed. The
identity-coding invariant prevents decompression expansion outside the byte budget.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Iterable, Iterator

import httpx

from egressweave.validation import EGRESS_NOT_ALLOWED, EgressNotAllowedError

_BODYLESS_RESPONSE_STATUS_CODES = frozenset({204, 304})


def _coerce_response_header_item(item: object) -> tuple[bytes, bytes] | None:
    """Return one exact byte header pair or ``None`` without leaking failures."""
    try:
        name, value = item  # type: ignore[misc]
    except Exception:  # noqa: BLE001
        return None
    if type(name) is not bytes or type(value) is not bytes:
        return None
    return name, value


def _enforce_response_header_limits(
    headers: Iterable[tuple[bytes, bytes]],
    max_response_header_fields: int,
    max_response_header_bytes: int,
) -> None:
    """Reject response metadata exceeding field-count or name/value budgets.

    RFC 9110 leaves received field limits to implementations. Repeated fields,
    including ``Set-Cookie``, count independently. The byte budget sums each
    decoded field name and value exactly once. Structural protocol overhead is
    controlled separately by the finite field count, keeping accounting stable
    across HTTP versions. Malformed downstream metadata, including an iterator
    that fails while yielding fields, is masked behind the same generic policy
    boundary as an exceeded budget.
    """
    denied = False
    field_bytes = 0
    try:
        for field_count, item in enumerate(headers, start=1):
            if field_count > max_response_header_fields:
                denied = True
                break
            normalized_item = _coerce_response_header_item(item)
            if normalized_item is None:
                denied = True
                break
            name, value = normalized_item
            field_bytes += len(name) + len(value)
            if field_bytes > max_response_header_bytes:
                denied = True
                break
    except Exception:  # noqa: BLE001
        denied = True

    if denied:
        raise EgressNotAllowedError(EGRESS_NOT_ALLOWED) from None


def _force_identity_accept_encoding(
    headers: Iterable[tuple[bytes, bytes]],
) -> list[tuple[bytes, bytes]]:
    """Replace caller compression preferences with one trusted identity request.

    The safe request-header builder has already validated every field and placed
    the trusted ``Host`` field last. This function removes all caller-supplied
    ``Accept-Encoding`` fields, adds ``identity``, and preserves ``Host`` as the
    final field. A server that ignores the request and returns a content-coded
    body is rejected by :func:`_enforce_declared_response_size` before HTTPX can
    allocate decompressed output outside the policy byte budget.
    """
    safe_headers: list[tuple[bytes, bytes]] = []
    trusted_host: tuple[bytes, bytes] | None = None
    for name, value in headers:
        normalized_name = name.lower()
        if normalized_name == b"accept-encoding":
            continue
        if normalized_name == b"host":
            trusted_host = (name, value)
            continue
        safe_headers.append((name, value))

    safe_headers.append((b"accept-encoding", b"identity"))
    if trusted_host is not None:
        safe_headers.append(trusted_host)
    return safe_headers


def _enforce_declared_response_size(
    request_method: str,
    status_code: int,
    headers: Iterable[tuple[bytes, bytes]],
    max_response_bytes: int,
) -> None:
    """Reject content coding or unsafe lengths before caller-visible delivery.

    RFC 9112 defines responses to ``HEAD`` and responses with informational,
    204, or 304 status codes as bodyless regardless of their fields. Their
    representation metadata is therefore not interpreted as transferred bytes.

    Every body-bearing response must be identity-coded: an absent
    ``Content-Encoding`` or exactly one canonical ``identity`` value is allowed.
    This pairs with the trusted ``Accept-Encoding: identity`` request field and
    prevents a compressed chunk from expanding beyond the policy limit before a
    post-decompression check can run. Exactly one canonical decimal
    ``Content-Length`` is accepted when present. Duplicate, comma-joined, signed,
    malformed, or over-budget values fail behind EgressWeave's generic rejection
    boundary.

    This metadata preflight is not the sole length control. A peer can omit or
    under-declare ``Content-Length`` or use chunked framing, so the bounded stream
    wrappers below count every transfer-decoded identity body chunk.
    """
    if (
        request_method == "HEAD"
        or 100 <= status_code < 200
        or status_code in _BODYLESS_RESPONSE_STATUS_CODES
    ):
        return

    header_items = tuple(headers)
    content_encoding_values = [
        value for name, value in header_items if name.lower() == b"content-encoding"
    ]
    if len(content_encoding_values) > 1:
        raise EgressNotAllowedError(EGRESS_NOT_ALLOWED)
    if content_encoding_values:
        content_encoding = content_encoding_values[0]
        if content_encoding != b"identity":
            raise EgressNotAllowedError(EGRESS_NOT_ALLOWED)

    content_length_values = [
        value for name, value in header_items if name.lower() == b"content-length"
    ]
    if not content_length_values:
        return
    if len(content_length_values) != 1:
        raise EgressNotAllowedError(EGRESS_NOT_ALLOWED)

    content_length = content_length_values[0]
    if not content_length or any(
        octet < ord("0") or octet > ord("9") for octet in content_length
    ):
        raise EgressNotAllowedError(EGRESS_NOT_ALLOWED)

    significant_length = content_length.lstrip(b"0")
    if significant_length:
        budget_text = str(max_response_bytes).encode("ascii")
        if len(significant_length) > len(budget_text) or (
            len(significant_length) == len(budget_text)
            and significant_length > budget_text
        ):
            raise EgressNotAllowedError(EGRESS_NOT_ALLOWED)


def _require_exact_response_chunk(chunk: object) -> bytes:
    """Return one exact built-in ``bytes`` chunk or fail closed.

    Response streams are dependency-injected and must therefore be treated as an
    untrusted runtime boundary even though HTTPX's interface is typed to yield
    bytes. An arbitrary object or ``bytes`` subclass can customize ``__len__``
    and make resource accounting disagree with the caller-visible byte buffer.
    Requiring the exact built-in type before measuring or exposing the chunk
    keeps the byte budget bound to Python's immutable native byte length and
    avoids invoking attacker-controlled conversion or length protocols.
    """
    if type(chunk) is not bytes:
        raise EgressNotAllowedError(EGRESS_NOT_ALLOWED) from None
    return chunk


def _close_sync_after_policy_denial(stream: httpx.SyncByteStream) -> None:
    """Best-effort close a denied sync stream without retaining backend errors."""
    try:
        stream.close()
    except BaseException:  # noqa: BLE001
        return


async def _close_async_after_policy_denial(stream: httpx.AsyncByteStream) -> None:
    """Consume child cleanup failures while preserving caller cancellation.

    Policy denial is already decided before this helper runs. A dependency-injected
    implementation may violate the static async-stream contract by raising while
    ``aclose`` is called, returning a non-awaitable value, or failing or
    self-cancelling after returning its awaitable. Those child outcomes are
    discarded. Cancellation directed at the coordinator while it awaits the
    gather still propagates to its caller.
    """
    try:
        close_awaitable = stream.aclose()
        cleanup = asyncio.gather(close_awaitable, return_exceptions=True)
    except BaseException:  # noqa: BLE001
        return
    _ = await cleanup


class _BoundedSyncResponseStream(httpx.SyncByteStream):
    """Count identity-coded sync response bytes and close on first unsafe chunk."""

    def __init__(
        self, stream: httpx.SyncByteStream, max_response_bytes: int
    ) -> None:
        """Store the wrapped HTTPX stream and its positive policy budget."""
        self._stream = stream
        self._max_response_bytes = max_response_bytes

    def __iter__(self) -> Iterator[bytes]:
        """Yield exact byte chunks until the next complete chunk is unsafe."""
        consumed_bytes = 0
        for chunk in self._stream:
            denied = False
            try:
                exact_chunk = _require_exact_response_chunk(chunk)
            except EgressNotAllowedError:
                denied = True
            if denied:
                _close_sync_after_policy_denial(self._stream)
                raise EgressNotAllowedError(EGRESS_NOT_ALLOWED) from None

            consumed_bytes += len(exact_chunk)
            if consumed_bytes > self._max_response_bytes:
                _close_sync_after_policy_denial(self._stream)
                raise EgressNotAllowedError(EGRESS_NOT_ALLOWED) from None
            yield exact_chunk

    def close(self) -> None:
        """Release the wrapped response stream and its pooled connection."""
        self._stream.close()


class _BoundedAsyncResponseStream(httpx.AsyncByteStream):
    """Count identity-coded async response bytes and close on unsafe chunks."""

    def __init__(
        self, stream: httpx.AsyncByteStream, max_response_bytes: int
    ) -> None:
        """Store the wrapped HTTPX stream and its positive policy budget."""
        self._stream = stream
        self._max_response_bytes = max_response_bytes

    async def __aiter__(self) -> AsyncIterator[bytes]:
        """Yield exact byte chunks until the next complete chunk is unsafe."""
        consumed_bytes = 0
        async for chunk in self._stream:
            denied = False
            try:
                exact_chunk = _require_exact_response_chunk(chunk)
            except EgressNotAllowedError:
                denied = True
            if denied:
                await _close_async_after_policy_denial(self._stream)
                raise EgressNotAllowedError(EGRESS_NOT_ALLOWED) from None

            consumed_bytes += len(exact_chunk)
            if consumed_bytes > self._max_response_bytes:
                await _close_async_after_policy_denial(self._stream)
                raise EgressNotAllowedError(EGRESS_NOT_ALLOWED) from None
            yield exact_chunk

    async def aclose(self) -> None:
        """Release the wrapped async stream and its pooled connection."""
        await self._stream.aclose()
