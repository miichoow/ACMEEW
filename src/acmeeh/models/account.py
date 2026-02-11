"""Account and AccountContact entities."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from uuid import UUID

    from acmeeh.core.types import AccountStatus

# Sentinel for timestamps not yet assigned by the database.
_EPOCH = datetime(1970, 1, 1)


@dataclass(frozen=True)
class Account:
    id: UUID
    jwk_thumbprint: str
    jwk: dict
    status: AccountStatus
    tos_agreed: bool = False
    created_at: datetime = _EPOCH
    updated_at: datetime = _EPOCH


@dataclass(frozen=True)
class AccountContact:
    id: UUID
    account_id: UUID
    contact_uri: str
    created_at: datetime = _EPOCH
