"""Multi-CA failover backend.

Wraps multiple CA backends and tries them in order. If the primary
backend fails with a retryable error, the next backend is tried.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from acmeeh.ca.base import CABackend, CAError, IssuedCertificate

if TYPE_CHECKING:
    from cryptography import x509

    from acmeeh.config.settings import CAProfileSettings, CASettings
    from acmeeh.core.types import RevocationReason

log = logging.getLogger(__name__)


class FailoverCABackend(CABackend):
    """Tries multiple CA backends in order, failing over on errors.

    Parameters
    ----------
    backends:
        Ordered list of (name, backend) tuples to try.
    ca_settings:
        The CA settings (passed to super).

    """

    def __init__(
        self,
        backends: list[tuple[str, CABackend]],
        ca_settings: CASettings,
    ) -> None:
        super().__init__(ca_settings)
        if not backends:
            msg = "FailoverCABackend requires at least one backend"
            raise CAError(msg)
        self._backends = backends
        self._healthy: dict[str, bool] = {name: True for name, _ in backends}

    def startup_check(self) -> None:
        """Check all backends and mark unhealthy ones."""
        for name, backend in self._backends:
            try:
                backend.startup_check()
                self._healthy[name] = True
            except CAError:
                self._healthy[name] = False
                log.warning("CA backend '%s' failed startup check", name)
        # At least one must be healthy
        if not any(self._healthy.values()):
            msg = "All CA backends failed startup check"
            raise CAError(msg)

    def sign(
        self,
        csr: x509.CertificateSigningRequest,
        *,
        profile: CAProfileSettings,
        validity_days: int,
        serial_number: int | None = None,
        ct_submitter=None,
    ) -> IssuedCertificate:
        """Try signing with each backend in order."""
        last_error: CAError | None = None
        for name, backend in self._backends:
            if not self._healthy.get(name, True):
                continue
            try:
                result = backend.sign(
                    csr,
                    profile=profile,
                    validity_days=validity_days,
                    serial_number=serial_number,
                    ct_submitter=ct_submitter,
                )
                log.debug("CA backend '%s' signed successfully", name)
                return result
            except CAError as exc:
                last_error = exc
                self._healthy[name] = False
                log.warning(
                    "CA backend '%s' failed to sign: %s (failover to next)",
                    name,
                    exc.detail,
                )
                continue
        raise last_error or CAError("All CA backends failed to sign")

    def revoke(
        self,
        *,
        serial_number: str,
        certificate_pem: str,
        reason: RevocationReason | None = None,
    ) -> None:
        """Try revoking with each backend (best-effort, try all)."""
        last_error: CAError | None = None
        for name, backend in self._backends:
            try:
                backend.revoke(
                    serial_number=serial_number,
                    certificate_pem=certificate_pem,
                    reason=reason,
                )
                return
            except CAError as exc:
                last_error = exc
                log.warning(
                    "CA backend '%s' failed to revoke: %s",
                    name,
                    exc.detail,
                )
                continue
        if last_error is not None:
            raise last_error
