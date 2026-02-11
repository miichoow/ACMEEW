"""Account service — ACME account lifecycle (RFC 8555 §7.3).

Handles account creation, lookup, contact update, and deactivation.
Enforces TOS agreement, contact validation, and key uniqueness.
"""

from __future__ import annotations

import base64
import json
import logging
import re
import secrets
from dataclasses import replace
from typing import TYPE_CHECKING, Any
from uuid import UUID, uuid4

from acmeeh.app.errors import (
    ACCOUNT_DOES_NOT_EXIST,
    EXTERNAL_ACCOUNT_REQUIRED,
    INVALID_CONTACT,
    MALFORMED,
    UNAUTHORIZED,
    UNSUPPORTED_CONTACT,
    AcmeProblem,
)
from acmeeh.core.jws import compute_thumbprint, validate_eab_jws
from acmeeh.core.types import AccountStatus, NotificationType
from acmeeh.logging import security_events
from acmeeh.models.account import Account, AccountContact

if TYPE_CHECKING:
    from acmeeh.config.settings import AccountSettings, EmailSettings, TosSettings
    from acmeeh.hooks.registry import HookRegistry
    from acmeeh.repositories.account import (
        AccountContactRepository,
        AccountRepository,
    )
    from acmeeh.repositories.authorization import AuthorizationRepository
    from acmeeh.services.notification import NotificationService

log = logging.getLogger(__name__)

_MAILTO_RE = re.compile(r"^mailto:([^@]+@[^@]+\.[^@]+)$", re.IGNORECASE)

_MAILTO_PREFIX = "mailto:"


class AccountService:
    """Manage ACME account lifecycle."""

    def __init__(  # noqa: PLR0913
        self,
        account_repo: AccountRepository,
        contact_repo: AccountContactRepository,
        email_settings: EmailSettings,
        tos_settings: TosSettings,
        notification_service: NotificationService | None = None,
        hook_registry: HookRegistry | None = None,
        eab_repo: Any = None,  # noqa: ANN401
        eab_required: bool = False,  # noqa: FBT001, FBT002
        eab_reusable: bool = False,  # noqa: FBT001, FBT002
        metrics: Any = None,  # noqa: ANN401
        authz_repo: AuthorizationRepository | None = None,
        account_settings: AccountSettings | None = None,
    ) -> None:
        """Initialize the account service with its dependencies."""
        self._accounts = account_repo
        self._contacts = contact_repo
        self._email = email_settings
        self._tos = tos_settings
        self._notifier = notification_service
        self._hooks = hook_registry
        self._eab_repo = eab_repo
        self._eab_required = eab_required
        self._eab_reusable = eab_reusable
        self._metrics = metrics
        self._authz_repo = authz_repo
        self._account_settings = account_settings

    def create_or_find(  # noqa: C901, PLR0912, PLR0915
        self,
        jwk: dict[str, Any],
        contact: list[str] | None = None,
        tos_agreed: bool = False,  # noqa: FBT001, FBT002
        eab_payload: dict[str, Any] | None = None,
    ) -> tuple[Account, list[AccountContact], bool]:
        """Create a new account or return existing one for the same key.

        Parameters
        ----------
        jwk:
            The account's JWK dictionary.
        contact:
            Optional list of ``mailto:`` URIs.
        tos_agreed:
            Whether the client agreed to the terms of service.

        Returns
        -------
        tuple
            ``(account, contacts, created)`` where *created* is True
            if a new account was just created.

        """
        thumbprint = compute_thumbprint(jwk)

        # Check for existing account with same key
        existing = self._accounts.find_by_thumbprint(thumbprint)
        if existing is not None:
            contacts = self._contacts.find_by_account(existing.id)
            return existing, contacts, False

        # Enforce TOS agreement
        if self._tos.require_agreement and not tos_agreed:
            raise AcmeProblem(
                MALFORMED,
                "Terms of service agreement is required; set 'termsOfServiceAgreed' to true",
            )

        # EAB validation
        if self._eab_required and eab_payload is None:
            raise AcmeProblem(
                EXTERNAL_ACCOUNT_REQUIRED,
                "External account binding is required",
            )

        eab_kid = None
        if eab_payload is not None and self._eab_repo is not None:
            eab_kid = self._parse_and_verify_eab(eab_payload, jwk)

        # Validate contacts
        try:
            contact_entities = self._validate_and_build_contacts(
                contact,
                account_id=None,
            )
        except AcmeProblem:
            if self._notifier and contact:
                self._notify_registration_failure(contact)
            raise

        # Enforce contact requirement
        if self._email.require_contact and not contact_entities:
            raise AcmeProblem(
                INVALID_CONTACT,
                "At least one contact email is required",
            )

        # Create account
        account_id = uuid4()
        account = Account(
            id=account_id,
            jwk_thumbprint=thumbprint,
            jwk=jwk,
            status=AccountStatus.VALID,
            tos_agreed=tos_agreed,
        )
        self._accounts.create(account)

        # Mark EAB credential as used
        if eab_kid is not None and self._eab_repo is not None and not self._eab_reusable:
            self._eab_repo.mark_used(eab_kid, account_id)

        # Create contacts
        created_contacts: list[AccountContact] = []
        for entity in contact_entities:
            entity = replace(entity, account_id=account_id)
            self._contacts.create(entity)
            created_contacts.append(entity)

        log.info(
            "Created account %s (thumbprint=%s)",
            account_id,
            thumbprint,
        )
        security_events.account_created(
            account_id,
            thumbprint,
            [c.contact_uri for c in created_contacts],
        )

        if self._metrics:
            self._metrics.increment("acmeeh_accounts_created_total")

        if self._notifier:
            contact_uris = [c.contact_uri for c in created_contacts]
            self._notifier.notify(
                NotificationType.REGISTRATION_SUCCEEDED,
                account_id,
                {
                    "account_id": str(account_id),
                    "contacts": contact_uris,
                },
            )

        if self._hooks:
            self._hooks.dispatch(
                "account.registration",
                {
                    "account_id": str(account_id),
                    "contacts": [c.contact_uri for c in created_contacts],
                    "jwk_thumbprint": thumbprint,
                    "tos_agreed": tos_agreed,
                },
            )

        return account, created_contacts, True

    def _parse_and_verify_eab(
        self,
        eab_payload: dict[str, Any],
        jwk: dict[str, Any],
    ) -> str:
        """Parse the EAB protected header and verify the HMAC binding.

        Returns the EAB kid on success.

        Raises
        ------
        AcmeProblem
            On malformed headers or invalid/revoked/already-used credentials.

        """
        try:
            inner_header = json.loads(
                base64.urlsafe_b64decode(
                    eab_payload.get("protected", "") + "==",
                ),
            )
            eab_kid: str = inner_header.get("kid", "")
        except (ValueError, json.JSONDecodeError) as err:
            raise AcmeProblem(
                MALFORMED,
                "Cannot parse EAB protected header",
            ) from err

        cred = self._eab_repo.find_by_kid(eab_kid)
        # Always perform HMAC verification to prevent timing-based
        # enumeration of valid EAB credentials
        hmac_key = (
            cred.hmac_key
            if cred is not None
            else base64.urlsafe_b64encode(
                secrets.token_bytes(32),  # noqa: PLR2004
            ).decode()
        )
        try:
            validate_eab_jws(eab_payload, jwk, hmac_key)
        except AcmeProblem:
            if cred is None:
                raise AcmeProblem(  # noqa: TRY301
                    UNAUTHORIZED,
                    "Invalid EAB credential",
                )
            raise
        if cred is None:
            raise AcmeProblem(UNAUTHORIZED, "Invalid EAB credential")
        if cred.revoked:
            raise AcmeProblem(
                UNAUTHORIZED,
                "EAB credential has been revoked",
            )
        if cred.used and not self._eab_reusable:
            raise AcmeProblem(
                UNAUTHORIZED,
                "EAB credential has already been used",
            )
        return eab_kid

    def _notify_registration_failure(
        self,
        contact: list[str],
    ) -> None:
        """Send a notification about a failed registration attempt."""
        recipients = [
            uri.removeprefix(_MAILTO_PREFIX)
            for uri in contact
            if uri.lower().startswith(_MAILTO_PREFIX)
        ]
        if recipients and self._notifier is not None:
            self._notifier.notify(
                NotificationType.REGISTRATION_FAILED,
                None,
                {
                    "error_detail": "Contact validation failed",
                    "contacts": contact,
                },
                explicit_recipients=recipients,
            )

    def find_by_jwk(self, jwk: dict[str, Any]) -> Account:
        """Find an account by its JWK (for ``onlyReturnExisting``).

        Raises
        ------
        AcmeProblem
            ``ACCOUNT_DOES_NOT_EXIST`` if no account matches.

        """
        thumbprint = compute_thumbprint(jwk)
        account = self._accounts.find_by_thumbprint(thumbprint)
        if account is None:
            raise AcmeProblem(
                ACCOUNT_DOES_NOT_EXIST,
                "No account exists for the provided key",
                status=400,
            )
        return account

    def find_by_id(self, account_id: UUID) -> Account:
        """Find an account by ID.

        Raises
        ------
        AcmeProblem
            ``ACCOUNT_DOES_NOT_EXIST`` if no account matches.

        """
        account = self._accounts.find_by_id(account_id)
        if account is None:
            raise AcmeProblem(
                ACCOUNT_DOES_NOT_EXIST,
                "Account not found",
                status=404,
            )
        return account

    def update_contacts(
        self,
        account_id: UUID,
        contacts: list[str],
    ) -> list[AccountContact]:
        """Replace all contacts for an account.

        Parameters
        ----------
        account_id:
            The account ID.
        contacts:
            New list of ``mailto:`` URIs.

        Returns
        -------
        list[AccountContact]
            The new contact entities.

        """
        if self._account_settings is not None and not self._account_settings.allow_contact_update:
            raise AcmeProblem(
                UNAUTHORIZED,
                "Account contact updates are disabled by server policy",
                status=403,
            )

        account = self.find_by_id(account_id)
        if account.status != AccountStatus.VALID:
            raise AcmeProblem(
                UNAUTHORIZED,
                "Account is not in valid status",
                status=403,
            )

        entities = self._validate_and_build_contacts(contacts, account_id)
        return self._contacts.replace_for_account(account_id, entities)

    def deactivate(self, account_id: UUID) -> Account:
        """Deactivate an account.

        Return the updated account.

        Raises
        ------
        AcmeProblem
            ``UNAUTHORIZED`` if account is not in valid status.

        """
        if self._account_settings is not None and not self._account_settings.allow_deactivation:
            raise AcmeProblem(
                UNAUTHORIZED,
                "Account deactivation is disabled by server policy",
                status=403,
            )

        result = self._accounts.deactivate(account_id)
        if result is None:
            raise AcmeProblem(
                UNAUTHORIZED,
                "Account cannot be deactivated (not in valid status)",
                status=403,
            )
        log.info("Deactivated account %s", account_id)
        security_events.account_deactivated(account_id)
        if self._metrics:
            self._metrics.increment(
                "acmeeh_accounts_deactivated_total",
            )

        # Cascade: deactivate all pending/valid authorizations
        if self._authz_repo is not None:
            deactivated_count = self._authz_repo.deactivate_for_account(account_id)
            if deactivated_count > 0:
                log.info(
                    "Cascaded deactivation: %d authorizations deactivated for account %s",
                    deactivated_count,
                    account_id,
                )

        return result

    def _validate_and_build_contacts(
        self,
        contact_uris: list[str] | None,
        account_id: UUID | None,
    ) -> list[AccountContact]:
        """Validate contact URIs and build entity objects.

        Return an empty list if *contact_uris* is None or empty.
        """
        if not contact_uris:
            return []

        entities: list[AccountContact] = []
        for uri in contact_uris:
            match = _MAILTO_RE.match(uri)
            if match is None:
                raise AcmeProblem(
                    UNSUPPORTED_CONTACT,
                    f"Contact URI must be a mailto: URI (got '{uri}')",
                )

            email_addr = match.group(1)

            # Check allowed domains
            if self._email.allowed_domains:
                domain = email_addr.rsplit("@", 1)[-1].lower()
                allowed = (d.lower() for d in self._email.allowed_domains)
                if domain not in allowed:
                    raise AcmeProblem(
                        INVALID_CONTACT,
                        f"Email domain '{domain}' is not in the allowed list",
                    )

            entities.append(
                AccountContact(
                    id=uuid4(),
                    account_id=account_id or UUID(int=0),
                    contact_uri=uri,
                ),
            )

        return entities
