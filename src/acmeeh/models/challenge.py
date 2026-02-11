"""Challenge entity."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from uuid import UUID

    from acmeeh.core.types import ChallengeStatus, ChallengeType

_EPOCH = datetime(1970, 1, 1)


@dataclass(frozen=True)
class Challenge:
    id: UUID
    authorization_id: UUID
    type: ChallengeType
    token: str
    status: ChallengeStatus
    error: dict | None = None
    validated_at: datetime | None = None
    retry_count: int = 0
    next_retry_at: datetime | None = None
    locked_by: str | None = None
    locked_at: datetime | None = None
    created_at: datetime = _EPOCH
    updated_at: datetime = _EPOCH
