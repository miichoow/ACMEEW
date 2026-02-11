"""Cursor-based pagination helpers for the Admin API.

Provides a :func:`paginate_query` helper that repositories use
to fetch pages, and a :func:`build_link_header` helper that routes
use to emit ``Link`` headers.

Cursor values are opaque base64-encoded ``id`` strings.
"""

from __future__ import annotations

import base64
from uuid import UUID


def encode_cursor(value: UUID) -> str:
    """Encode a UUID into an opaque cursor string."""
    return base64.urlsafe_b64encode(str(value).encode()).decode().rstrip("=")


def decode_cursor(cursor: str) -> UUID:
    """Decode an opaque cursor string back to a UUID.

    Raises ``ValueError`` if the cursor is malformed.
    """
    padded = cursor + "=" * (4 - len(cursor) % 4)
    raw = base64.urlsafe_b64decode(padded).decode()
    return UUID(raw)


def build_link_header(
    base_url: str,
    next_cursor: str | None,
    limit: int,
) -> str | None:
    """Build an RFC 8288 ``Link`` header for the next page.

    Returns ``None`` when there is no next page.
    """
    if next_cursor is None:
        return None
    return f'<{base_url}?cursor={next_cursor}&limit={limit}>;rel="next"'
