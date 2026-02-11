"""ACME Renewal Information service (draft-ietf-acme-ari).

Computes suggested renewal windows based on certificate validity
and revocation status.
"""

from __future__ import annotations

import base64
import logging
from datetime import UTC, datetime
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from acmeeh.config.settings import AriSettings
    from acmeeh.repositories.certificate import CertificateRepository

log = logging.getLogger(__name__)


class RenewalInfoService:
    """Computes ARI renewal windows for certificates."""

    def __init__(
        self,
        cert_repo: CertificateRepository,
        settings: AriSettings,
    ) -> None:
        self._certs = cert_repo
        self._settings = settings

    def get_renewal_info(self, cert_id: str) -> dict | None:
        """Compute renewal info for a certID.

        Parameters
        ----------
        cert_id:
            Base64url-encoded ``AKI.keyIdentifier || '.' || serialNumber``
            as defined in draft-ietf-acme-ari.

        Returns
        -------
        dict or None
            Renewal info with suggestedWindow, or None if cert not found.

        """
        # Parse certID: base64url decode, split on '.'
        try:
            decoded = base64.urlsafe_b64decode(cert_id + "==").decode("ascii")
            parts = decoded.split(".")
            if len(parts) != 2:
                return None
            serial_hex = parts[1]
        except Exception:
            # Try treating it directly as a serial
            serial_hex = cert_id

        cert = self._certs.find_by_serial(serial_hex)
        if cert is None:
            return None

        now = datetime.now(UTC)

        # Compute suggested window
        validity_duration = (cert.not_after_cert - cert.not_before_cert).total_seconds()
        renewal_offset = validity_duration * self._settings.renewal_percentage

        window_start = cert.not_after_cert.timestamp() - renewal_offset
        window_start_dt = datetime.fromtimestamp(window_start, tz=UTC)
        window_end_dt = cert.not_after_cert

        # If cert is revoked, window starts now
        if cert.revoked_at is not None:
            window_start_dt = now

        # Compute retry-after (seconds until window start, min 1 hour)
        retry_after = max(int((window_start_dt - now).total_seconds()), 3600)

        return {
            "suggestedWindow": {
                "start": window_start_dt.isoformat(),
                "end": window_end_dt.isoformat(),
            },
            "retryAfter": retry_after,
        }

    def should_renew(self, cert_id: str) -> bool:
        """Check if a certificate should be renewed now.

        Parameters
        ----------
        cert_id:
            The certID string (serial number or ARI-encoded ID).

        Returns
        -------
        bool
            True if the certificate is within its suggested renewal window.

        """
        info = self.get_renewal_info(cert_id)
        if info is None:
            return False

        now = datetime.now(UTC)
        window_start = datetime.fromisoformat(info["suggestedWindow"]["start"])
        return now >= window_start
