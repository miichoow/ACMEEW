"""Certificate entity."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from uuid import UUID

    from acmeeh.core.types import RevocationReason

_EPOCH = datetime(1970, 1, 1)


@dataclass(frozen=True)
class Certificate:
    id: UUID
    account_id: UUID
    order_id: UUID
    serial_number: str
    fingerprint: str
    pem_chain: str
    not_before_cert: datetime
    not_after_cert: datetime
    revoked_at: datetime | None = None
    revocation_reason: RevocationReason | None = None
    public_key_fingerprint: str | None = None
    san_values: list | None = None
    created_at: datetime = _EPOCH
    updated_at: datetime = _EPOCH
