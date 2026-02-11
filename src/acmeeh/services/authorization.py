"""Authorization service — ACME authorization lifecycle (RFC 8555 §7.5).

Handles authorization retrieval, deactivation, and readiness checks
for orders.
"""

from __future__ import annotations

import logging
from datetime import UTC
from typing import TYPE_CHECKING
from uuid import UUID, uuid4

from acmeeh.app.errors import MALFORMED, UNAUTHORIZED, AcmeProblem
from acmeeh.core.types import AuthorizationStatus
from acmeeh.models.authorization import Authorization
from acmeeh.models.challenge import Challenge

if TYPE_CHECKING:
    from acmeeh.repositories.authorization import AuthorizationRepository
    from acmeeh.repositories.challenge import ChallengeRepository

log = logging.getLogger(__name__)


class AuthorizationService:
    """Manages ACME authorization lifecycle."""

    def __init__(
        self,
        authz_repo: AuthorizationRepository,
        challenge_repo: ChallengeRepository,
        pre_authorization_lifetime_days: int = 30,
    ) -> None:
        self._authz = authz_repo
        self._challenges = challenge_repo
        self._pre_auth_lifetime_days = pre_authorization_lifetime_days

    def get_authorization(
        self,
        authz_id: UUID,
        account_id: UUID,
    ) -> tuple[Authorization, list[Challenge]]:
        """Get an authorization with ownership check.

        Returns
        -------
        tuple
            ``(authorization, challenges)``

        Raises
        ------
        AcmeProblem
            ``MALFORMED`` if not found, ``UNAUTHORIZED`` if wrong account.

        """
        authz = self._authz.find_by_id(authz_id)
        if authz is None:
            raise AcmeProblem(MALFORMED, "Authorization not found", status=404)
        if authz.account_id != account_id:
            raise AcmeProblem(
                UNAUTHORIZED,
                "Authorization does not belong to this account",
                status=403,
            )
        challenges = self._challenges.find_by_authorization(authz_id)
        return authz, challenges

    def check_order_ready(self, order_id: UUID) -> bool:
        """Check if all authorizations for an order are valid.

        Returns True if every authorization linked to the order has
        status ``valid``. Uses a single COUNT query for efficiency.
        """
        return self._authz.all_valid_for_order(order_id)

    def deactivate(self, authz_id: UUID, account_id: UUID) -> Authorization:
        """Deactivate an authorization.

        Only pending or valid authorizations can be deactivated.

        Returns the updated authorization.
        """
        authz = self._authz.find_by_id(authz_id)
        if authz is None:
            raise AcmeProblem(MALFORMED, "Authorization not found", status=404)
        if authz.account_id != account_id:
            raise AcmeProblem(
                UNAUTHORIZED,
                "Authorization does not belong to this account",
                status=403,
            )

        # Try from pending first, then from valid
        result = self._authz.transition_status(
            authz_id,
            AuthorizationStatus.PENDING,
            AuthorizationStatus.DEACTIVATED,
        )
        if result is None:
            result = self._authz.transition_status(
                authz_id,
                AuthorizationStatus.VALID,
                AuthorizationStatus.DEACTIVATED,
            )
        if result is None:
            raise AcmeProblem(
                MALFORMED,
                f"Authorization cannot be deactivated from status '{authz.status.value}'",
            )

        log.info("Deactivated authorization %s", authz_id)
        return result

    def create_pre_authorization(
        self,
        account_id: UUID,
        identifier_type: str,
        identifier_value: str,
    ) -> tuple[Authorization, list[Challenge]]:
        """Create a standalone pre-authorization with challenges.

        Returns (authorization, challenges).
        """
        import secrets
        from datetime import datetime, timedelta

        from acmeeh.core.types import ChallengeStatus, ChallengeType, IdentifierType

        # Normalize DNS identifiers: IDN to punycode, then lowercase
        if identifier_type == "dns":
            from acmeeh.services.order import _normalize_idn

            identifier_value = _normalize_idn(identifier_value)

        # Check for existing reusable authorization
        id_type = IdentifierType(identifier_type)
        reusable = self._authz.find_reusable(account_id, id_type, identifier_value)
        if reusable is not None:
            challenges = self._challenges.find_by_authorization(reusable.id)
            return reusable, challenges

        # Create new authorization
        authz_id = uuid4()
        authz_expires = datetime.now(UTC) + timedelta(days=self._pre_auth_lifetime_days)

        is_wildcard = identifier_type == "dns" and identifier_value.startswith("*.")
        authz_value = identifier_value[2:] if is_wildcard else identifier_value

        authz = Authorization(
            id=authz_id,
            account_id=account_id,
            identifier_type=id_type,
            identifier_value=authz_value,
            status=AuthorizationStatus.PENDING,
            expires=authz_expires,
            wildcard=is_wildcard,
        )
        self._authz.create(authz)

        # Create challenges
        challenge_types = [ChallengeType.HTTP_01, ChallengeType.DNS_01]
        created_challenges = []
        for ctype in challenge_types:
            # Skip HTTP-01 for wildcards
            if ctype == ChallengeType.HTTP_01 and is_wildcard:
                continue
            # Skip DNS-01 for IP identifiers
            if ctype == ChallengeType.DNS_01 and identifier_type == "ip":
                continue

            token = secrets.token_urlsafe(32)
            challenge = Challenge(
                id=uuid4(),
                authorization_id=authz_id,
                type=ctype,
                token=token,
                status=ChallengeStatus.PENDING,
            )
            self._challenges.create(challenge)
            created_challenges.append(challenge)

        log.info(
            "Created pre-authorization %s for %s:%s with %d challenges",
            authz_id,
            identifier_type,
            identifier_value,
            len(created_challenges),
        )

        return authz, created_challenges
