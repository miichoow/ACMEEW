r"""External CA backend — forwards signing and revocation to an upstream CA.

Supports enterprise PKI workflows by communicating with an external
certificate authority over HTTPS.  Authentication options include:

- **Header-based auth**: API tokens, Bearer tokens, custom headers
  (configured via ``auth_header`` / ``auth_value``)
- **Mutual TLS (mTLS)**: Client certificate + key for strong identity
  (configured via ``client_cert_path`` / ``client_key_path``)
- **Custom CA trust**: Pin the upstream CA's TLS certificate
  (configured via ``ca_cert_path``)

API contract
------------
**Sign** — ``POST {sign_url}``

Request body (JSON)::

    {
        "csr": "-----BEGIN CERTIFICATE REQUEST-----\\n...",
        "profile": "default",
        "validity_days": 90
    }

Response body (JSON, HTTP 200)::

    {
        "certificate_chain": "-----BEGIN CERTIFICATE-----\\n..."
    }

The ``certificate_chain`` field contains the full PEM chain (leaf +
intermediates).  Serial number, validity, and fingerprint are parsed
from the leaf certificate.

**Revoke** — ``POST {revoke_url}``

Request body (JSON)::

    {
        "serial_number": "0a1b2c...",
        "reason": 0
    }

Response: HTTP 200 on success.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import logging
import ssl
import urllib.error
import urllib.request
from typing import TYPE_CHECKING

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from acmeeh.ca.base import CABackend, CAError, IssuedCertificate

if TYPE_CHECKING:
    from acmeeh.config.settings import CAProfileSettings, CASettings
    from acmeeh.core.types import RevocationReason

log = logging.getLogger(__name__)


class ExternalCABackend(CABackend):
    """Forwards certificate operations to an external CA over HTTPS.

    Designed for enterprise PKI integration — supports mTLS, custom
    auth headers, and configurable TLS trust anchors.
    """

    def __init__(self, ca_settings: CASettings) -> None:
        super().__init__(ca_settings)
        self._ext = ca_settings.external
        self._ssl_ctx: ssl.SSLContext | None = None

    def startup_check(self) -> None:
        """Verify external CA settings are configured."""
        if not self._ext.sign_url:
            msg = "ca.external.sign_url is required for the external CA backend"
            raise CAError(
                msg,
            )

    def _get_ssl_context(self) -> ssl.SSLContext:
        """Build (and cache) an SSL context with mTLS and CA trust config."""
        if self._ssl_ctx is not None:
            return self._ssl_ctx

        ctx = ssl.create_default_context()

        # Custom CA trust anchor
        if self._ext.ca_cert_path:
            ctx.load_verify_locations(self._ext.ca_cert_path)

        # mTLS client certificate
        if self._ext.client_cert_path and self._ext.client_key_path:
            ctx.load_cert_chain(
                self._ext.client_cert_path,
                self._ext.client_key_path,
            )

        self._ssl_ctx = ctx
        return ctx

    def _build_request(
        self,
        url: str,
        payload: dict,
    ) -> urllib.request.Request:
        """Build an HTTPS request with auth headers and JSON body."""
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=data,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
        )
        # Add auth header if configured
        if self._ext.auth_value:
            req.add_header(self._ext.auth_header, self._ext.auth_value)
        return req

    def _do_request(self, url: str, payload: dict) -> dict:
        """Send a JSON request with retry logic and return parsed JSON."""
        max_retries = self._ext.max_retries
        delay = self._ext.retry_delay_seconds
        last_exc = None

        for attempt in range(max_retries + 1):
            try:
                return self._do_single_request(url, payload)
            except CAError as exc:
                if not exc.retryable or attempt == max_retries:
                    raise
                last_exc = exc
                log.warning(
                    "External CA attempt %d/%d failed: %s",
                    attempt + 1,
                    max_retries + 1,
                    exc.detail,
                )
                import time

                time.sleep(delay * (2**attempt))

        raise last_exc  # type: ignore[misc]

    def _do_single_request(self, url: str, payload: dict) -> dict:
        """Send a single JSON request and return the parsed JSON response."""
        req = self._build_request(url, payload)
        ctx = self._get_ssl_context()
        handler = urllib.request.HTTPSHandler(context=ctx)
        opener = urllib.request.build_opener(handler)

        try:
            resp = opener.open(req, timeout=self._ext.timeout_seconds)
        except urllib.error.HTTPError as exc:
            body = ""
            with contextlib.suppress(Exception):
                body = exc.read().decode("utf-8", errors="replace")[:500]
            msg = f"External CA returned HTTP {exc.code}: {body}"
            raise CAError(
                msg,
                retryable=exc.code >= 500,
            ) from exc
        except (urllib.error.URLError, OSError) as exc:
            msg = f"Failed to reach external CA at {url}: {exc}"
            raise CAError(
                msg,
                retryable=True,
            ) from exc

        if resp.status != 200:
            msg = f"External CA returned unexpected HTTP {resp.status}"
            raise CAError(
                msg,
                retryable=resp.status >= 500,
            )

        try:
            resp_body = resp.read().decode("utf-8")
            return json.loads(resp_body)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            msg = f"External CA returned invalid JSON response: {exc}"
            raise CAError(
                msg,
                retryable=False,
            ) from exc

    def sign(
        self,
        csr: x509.CertificateSigningRequest,
        *,
        profile: CAProfileSettings,
        validity_days: int,
        serial_number: int | None = None,
        ct_submitter=None,
    ) -> IssuedCertificate:
        """Forward a CSR to the external CA for signing.

        The ``serial_number`` parameter is ignored — the external CA
        assigns its own serial.  The actual serial is parsed from the
        returned leaf certificate.

        The ``ct_submitter`` parameter is accepted for interface
        compatibility but ignored — CT submission is not applicable
        to external CA backends.
        """
        if not self._ext.sign_url:
            msg = "ca.external.sign_url is not configured"
            raise CAError(
                msg,
            )

        # Encode CSR to PEM
        csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode("ascii")

        # Determine profile name (use first key usage as hint, or "default")
        profile_name = "default"
        if profile.extended_key_usages:
            profile_name = profile.extended_key_usages[0]

        payload = {
            "csr": csr_pem,
            "profile": profile_name,
            "validity_days": validity_days,
        }

        log.debug("Forwarding CSR to external CA: %s", self._ext.sign_url)
        resp_data = self._do_request(self._ext.sign_url, payload)

        # Extract PEM chain from response
        pem_chain = resp_data.get("certificate_chain", "")
        if not pem_chain:
            msg = "External CA response missing 'certificate_chain' field"
            raise CAError(
                msg,
                retryable=False,
            )

        # Parse leaf certificate to extract metadata
        try:
            leaf_cert = x509.load_pem_x509_certificate(pem_chain.encode("ascii"))
        except Exception as exc:
            msg = f"Failed to parse leaf certificate from external CA response: {exc}"
            raise CAError(
                msg,
                retryable=False,
            ) from exc

        leaf_der = leaf_cert.public_bytes(serialization.Encoding.DER)
        fingerprint = hashlib.sha256(leaf_der).hexdigest()
        serial_str = format(leaf_cert.serial_number, "x")

        log.info(
            "External CA signed certificate: serial=%s, subject=%s",
            serial_str,
            leaf_cert.subject,
        )

        return IssuedCertificate(
            pem_chain=pem_chain,
            not_before=leaf_cert.not_valid_before_utc,
            not_after=leaf_cert.not_valid_after_utc,
            serial_number=serial_str,
            fingerprint=fingerprint,
        )

    def revoke(
        self,
        *,
        serial_number: str,
        certificate_pem: str,
        reason: RevocationReason | None = None,
    ) -> None:
        """Forward a revocation request to the external CA."""
        if not self._ext.revoke_url:
            log.warning(
                "External CA revoke_url not configured — revocation "
                "recorded in database only (serial=%s)",
                serial_number,
            )
            return

        payload: dict = {
            "serial_number": serial_number,
        }
        if reason is not None:
            payload["reason"] = reason.value

        log.debug(
            "Forwarding revocation to external CA: serial=%s",
            serial_number,
        )
        self._do_request(self._ext.revoke_url, payload)

        log.info(
            "External CA acknowledged revocation: serial=%s, reason=%s",
            serial_number,
            reason.name if reason else "unspecified",
        )
