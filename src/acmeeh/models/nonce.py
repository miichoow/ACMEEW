"""Nonce entity."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from datetime import datetime


@dataclass(frozen=True)
class Nonce:
    nonce: str
    expires_at: datetime
    created_at: datetime | None = None
