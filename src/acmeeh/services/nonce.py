"""Nonce service — create, consume, and garbage-collect replay nonces.

Each ACME request must carry a fresh nonce in the JWS protected
header.  The server issues nonces via ``Replay-Nonce`` headers and
consumes them exactly once.

Nonces have a configurable TTL (``expiry_seconds``) and a hard
maximum age (``max_age_seconds``, default 300s) that rejects nonces
older than the threshold even before the GC has cleaned them up.

Usage::

    svc = NonceService(nonce_repo, nonce_settings)
    token = svc.create()         # issue a new nonce
    ok    = svc.consume(token)   # consume (True if valid)
    n     = svc.gc()             # delete expired nonces
"""

from __future__ import annotations

import logging
import secrets
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from acmeeh.config.settings import NonceSettings
    from acmeeh.repositories.nonce import NonceRepository

from acmeeh.models.nonce import Nonce

log = logging.getLogger(__name__)


class NonceService:
    """Manages ACME replay nonces with strict TTL enforcement."""

    def __init__(
        self,
        nonce_repo: NonceRepository,
        settings: NonceSettings,
    ) -> None:
        self._repo = nonce_repo
        self._settings = settings
        # Hard max-age cap — prevents replay even if expiry_seconds is generous
        self._max_age = timedelta(
            seconds=getattr(settings, "max_age_seconds", 0) or min(settings.expiry_seconds, 300),
        )

    def create(self) -> str:
        """Create and persist a new nonce.

        Returns the nonce token string (suitable for a ``Replay-Nonce``
        header).
        """
        token = secrets.token_urlsafe(self._settings.length)
        now = datetime.now(UTC)
        expires_at = now + timedelta(seconds=self._settings.expiry_seconds)
        nonce = Nonce(nonce=token, expires_at=expires_at, created_at=now)
        self._repo.create(nonce)
        return token

    def consume(self, nonce_value: str) -> bool:
        """Consume a nonce (exactly-once semantics) with strict TTL.

        The nonce must:
        1. Exist in the database
        2. Not be past its ``expires_at`` timestamp (enforced in SQL)
        3. Not be older than ``max_age_seconds`` (enforced here
           as defense-in-depth in case expiry_seconds > max_age)

        Returns True if the nonce was valid and consumed, False otherwise.
        """
        # Retrieve the nonce entity before consuming so we can check created_at
        nonce_entity = self._repo.find_by_id(nonce_value)
        if nonce_entity is None:
            return False

        # Explicit max-age freshness check (defense-in-depth)
        if nonce_entity.created_at is not None:
            age = datetime.now(UTC) - nonce_entity.created_at
            if age > self._max_age:
                # Nonce is too old — delete it and reject
                self._repo.consume(nonce_value)
                log.info(
                    "Nonce rejected: age %s exceeds max_age %s",
                    age,
                    self._max_age,
                )
                return False

        # Atomically consume (SQL enforces expires_at > now())
        return self._repo.consume(nonce_value)

    def gc(self) -> int:
        """Garbage-collect expired nonces.

        Returns the number of deleted nonces.
        """
        return self._repo.gc_expired()
