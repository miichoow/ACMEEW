"""OCSP responder service.

Parses OCSP requests, looks up certificate status, and builds
signed OCSP responses using the CA root key.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509 import ocsp

if TYPE_CHECKING:
    from acmeeh.config.settings import OcspSettings
    from acmeeh.repositories.certificate import CertificateRepository

log = logging.getLogger(__name__)

_HASH_MAP = {
    "sha256": hashes.SHA256(),
    "sha384": hashes.SHA384(),
    "sha512": hashes.SHA512(),
}


class OCSPService:
    """Builds OCSP responses for certificate status queries."""

    def __init__(
        self,
        cert_repo: CertificateRepository,
        root_cert: x509.Certificate,
        root_key,
        settings: OcspSettings,
    ) -> None:
        self._certs = cert_repo
        self._root_cert = root_cert
        self._root_key = root_key
        self._settings = settings
        self._hash_alg = _HASH_MAP.get(settings.hash_algorithm, hashes.SHA256())

    def handle_request(self, ocsp_request_der: bytes) -> bytes:
        """Process an OCSP request and return a DER-encoded response.

        Parameters
        ----------
        ocsp_request_der:
            DER-encoded OCSP request bytes.

        Returns
        -------
        bytes
            DER-encoded OCSP response.

        """
        try:
            ocsp_req = ocsp.load_der_ocsp_request(ocsp_request_der)
        except Exception as exc:
            log.warning("Failed to parse OCSP request: %s", exc)
            return self._build_error_response(ocsp.OCSPResponseStatus.MALFORMED_REQUEST)

        serial = ocsp_req.serial_number
        serial_hex = format(serial, "x")

        cert = self._certs.find_by_serial(serial_hex)

        now = datetime.now(UTC)
        next_update = now + timedelta(seconds=self._settings.response_validity_seconds)

        try:
            builder = ocsp.OCSPResponseBuilder()

            if cert is None:
                # Unknown certificate
                builder = builder.add_response(
                    cert=self._root_cert,
                    issuer=self._root_cert,
                    algorithm=hashes.SHA256(),
                    cert_status=ocsp.OCSPCertStatus.UNKNOWN,
                    this_update=now,
                    next_update=next_update,
                    revocation_time=None,
                    revocation_reason=None,
                )
            elif cert.revoked_at is not None:
                # Revoked certificate
                reason = None
                if cert.revocation_reason is not None:
                    try:
                        reason = x509.ReasonFlags(
                            x509.ReasonFlags(cert.revocation_reason.name.lower())
                        )
                    except (ValueError, AttributeError):
                        reason = None

                builder = builder.add_response(
                    cert=self._root_cert,
                    issuer=self._root_cert,
                    algorithm=hashes.SHA256(),
                    cert_status=ocsp.OCSPCertStatus.REVOKED,
                    this_update=now,
                    next_update=next_update,
                    revocation_time=cert.revoked_at,
                    revocation_reason=reason,
                )
            else:
                # Good certificate
                builder = builder.add_response(
                    cert=self._root_cert,
                    issuer=self._root_cert,
                    algorithm=hashes.SHA256(),
                    cert_status=ocsp.OCSPCertStatus.GOOD,
                    this_update=now,
                    next_update=next_update,
                    revocation_time=None,
                    revocation_reason=None,
                )

            builder = builder.responder_id(
                ocsp.OCSPResponderEncoding.HASH,
                self._root_cert,
            )

            response = builder.sign(self._root_key, self._hash_alg)
            return response.public_bytes(serialization.Encoding.DER)

        except Exception as exc:
            log.exception("Failed to build OCSP response: %s", exc)
            return self._build_error_response(ocsp.OCSPResponseStatus.INTERNAL_ERROR)

    @staticmethod
    def _build_error_response(status: ocsp.OCSPResponseStatus) -> bytes:
        """Build an error OCSP response."""
        response = ocsp.OCSPResponseBuilder.build_unsuccessful(status)
        return response.public_bytes(serialization.Encoding.DER)
