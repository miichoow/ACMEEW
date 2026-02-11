"""Order entity and Identifier value object."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from uuid import UUID

    from acmeeh.core.types import IdentifierType, OrderStatus

_EPOCH = datetime(1970, 1, 1)


@dataclass(frozen=True)
class Identifier:
    """ACME identifier value object (not persisted standalone)."""

    type: IdentifierType
    value: str


@dataclass(frozen=True)
class Order:
    id: UUID
    account_id: UUID
    status: OrderStatus
    identifiers: tuple[Identifier, ...]
    identifiers_hash: str
    expires: datetime | None = None
    not_before: datetime | None = None
    not_after: datetime | None = None
    error: dict | None = None
    certificate_id: UUID | None = None
    replaces: str | None = None
    created_at: datetime = _EPOCH
    updated_at: datetime = _EPOCH
