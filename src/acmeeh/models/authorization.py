"""Authorization entity."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from uuid import UUID

    from acmeeh.core.types import AuthorizationStatus, IdentifierType

_EPOCH = datetime(1970, 1, 1)


@dataclass(frozen=True)
class Authorization:
    id: UUID
    account_id: UUID
    identifier_type: IdentifierType
    identifier_value: str
    status: AuthorizationStatus
    expires: datetime | None = None
    wildcard: bool = False
    created_at: datetime = _EPOCH
    updated_at: datetime = _EPOCH
