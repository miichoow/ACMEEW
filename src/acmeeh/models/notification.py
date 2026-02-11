"""Notification entity."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING

from acmeeh.core.types import NotificationStatus, NotificationType

if TYPE_CHECKING:
    from uuid import UUID

_EPOCH = datetime(1970, 1, 1)


@dataclass(frozen=True)
class Notification:
    id: UUID
    notification_type: NotificationType
    recipient: str
    subject: str
    body: str
    status: NotificationStatus = NotificationStatus.PENDING
    account_id: UUID | None = None
    error_detail: str | None = None
    retry_count: int = 0
    created_at: datetime = _EPOCH
    sent_at: datetime | None = None
