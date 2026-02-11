"""CT Pre-Certificate submission (RFC 6962).

Handles the synchronous pre-certificate flow:
1. Build cert with CT poison extension
2. Sign with CA key
3. Submit to CT logs
4. Collect SCTs
5. Build final cert with SCT list extension
"""

from __future__ import annotations

import base64
import contextlib
import json
import logging
import struct
import urllib.error
import urllib.request
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from acmeeh.config.settings import CtLoggingSettings

log = logging.getLogger(__name__)


class CTPreCertSubmitter:
    """Submits pre-certificates to CT logs and collects SCTs.

    Used during the internal CA signing flow when
    ``ct_logging.submit_precert`` is enabled.  Each configured CT log
    receives the pre-certificate DER via ``/ct/v1/add-pre-chain`` and
    returns a Signed Certificate Timestamp (SCT).

    Parameters
    ----------
    ct_settings:
        The ``ct_logging`` configuration section containing the list
        of CT logs and their settings.

    """

    def __init__(self, ct_settings: CtLoggingSettings) -> None:
        self._settings = ct_settings

    def submit_precert(self, precert_der: bytes) -> list[dict]:
        """Submit a pre-certificate to all configured CT logs.

        Parameters
        ----------
        precert_der:
            DER-encoded pre-certificate (with CT poison extension).

        Returns
        -------
        list[dict]
            List of SCT dictionaries, one per successful CT log
            submission.  Each dict contains ``sct_version``, ``id``,
            ``timestamp``, ``extensions``, and ``signature``.

        """
        scts: list[dict] = []
        precert_b64 = base64.b64encode(precert_der).decode("ascii")

        for ct_log in self._settings.logs:
            try:
                sct = self._submit_to_log(ct_log, precert_b64)
                if sct is not None:
                    scts.append(sct)
            except urllib.error.HTTPError as exc:
                log.warning(
                    "CT pre-cert submission to %s failed with HTTP %d "
                    "(retryable=%s); continuing with remaining logs",
                    ct_log.url,
                    exc.code,
                    exc.code >= 500,
                    exc_info=True,
                )
            except urllib.error.URLError as exc:
                log.warning(
                    "CT pre-cert submission to %s failed: network error "
                    "(retryable=True): %s; continuing with remaining logs",
                    ct_log.url,
                    exc.reason,
                )
            except json.JSONDecodeError as exc:
                log.exception(
                    "CT pre-cert submission to %s returned invalid JSON "
                    "(retryable=False): %s; continuing with remaining logs",
                    ct_log.url,
                    exc,
                )
            except (OSError, ValueError) as exc:
                log.warning(
                    "CT pre-cert submission to %s failed: %s "
                    "(retryable=True); continuing with remaining logs",
                    ct_log.url,
                    exc,
                )

        return scts

    def _submit_to_log(self, ct_log, precert_b64: str) -> dict | None:
        """Submit the pre-certificate to a single CT log.

        Parameters
        ----------
        ct_log:
            A ``CtLogEntry`` from settings.
        precert_b64:
            Base64-encoded DER pre-certificate.

        Returns
        -------
        dict or None
            The parsed SCT response, or ``None`` on failure.

        """
        url = ct_log.url.rstrip("/") + "/ct/v1/add-pre-chain"
        timeout = ct_log.timeout_seconds

        payload = json.dumps({"chain": [precert_b64]}).encode("utf-8")

        req = urllib.request.Request(
            url,
            data=payload,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
        )

        try:
            resp = urllib.request.urlopen(req, timeout=timeout)
            resp_body = resp.read().decode("utf-8")
            sct = json.loads(resp_body)
            log.info(
                "CT pre-cert submission succeeded: log=%s sct_version=%s",
                ct_log.url,
                sct.get("sct_version", "?"),
            )
            return sct
        except urllib.error.HTTPError as exc:
            body = ""
            with contextlib.suppress(OSError):
                body = exc.read().decode("utf-8", errors="replace")[:200]
            log.warning(
                "CT log %s returned HTTP %d: %s",
                ct_log.url,
                exc.code,
                body,
            )
            raise
        except urllib.error.URLError as exc:
            log.warning(
                "CT pre-cert submission to %s failed: network error: %s",
                ct_log.url,
                exc.reason,
            )
            raise
        except json.JSONDecodeError as exc:
            log.exception(
                "CT log %s returned invalid JSON: %s",
                ct_log.url,
                exc,
            )
            raise
        except OSError as exc:
            log.warning(
                "CT pre-cert submission to %s failed: %s",
                ct_log.url,
                exc,
            )
            raise


def encode_sct_list(scts: list[dict]) -> bytes:
    """Encode a list of SCT dicts into TLS ``SignedCertificateTimestampList``.

    The wire format (RFC 6962 section 3.3) is::

        opaque SerializedSCT<1..2^16-1>;
        struct { SerializedSCT sct_list<1..2^16-1>; } SignedCertificateTimestampList;

    Each serialised SCT is::

        struct {
            Version sct_version;            // 1 byte (v1 = 0)
            LogID id;                       // 32 bytes
            uint64 timestamp;               // 8 bytes
            opaque extensions<0..2^16-1>;   // 2-byte length + data
            digitally-signed struct { ... } // hash_alg(1) + sig_alg(1) + sig_len(2) + sig
        } SignedCertificateTimestamp;

    Parameters
    ----------
    scts:
        List of SCT response dicts from CT logs.  Expected keys:
        ``sct_version``, ``id``, ``timestamp``, ``extensions``,
        ``signature``.

    Returns
    -------
    bytes
        TLS-encoded ``SignedCertificateTimestampList``.

    """
    serialized_scts: list[bytes] = []

    for sct in scts:
        parts = bytearray()

        # Version (1 byte)
        version = sct.get("sct_version", 0)
        parts.append(version & 0xFF)

        # Log ID (32 bytes, base64-encoded in response)
        log_id_b64 = sct.get("id", "")
        log_id = base64.b64decode(log_id_b64)
        if len(log_id) != 32:
            log.warning(
                "SCT log_id has unexpected length %d (expected 32); padding/truncating",
                len(log_id),
            )
            log_id = log_id[:32].ljust(32, b"\x00")
        parts.extend(log_id)

        # Timestamp (8 bytes, uint64 milliseconds since epoch)
        timestamp = sct.get("timestamp", 0)
        parts.extend(struct.pack(">Q", timestamp))

        # Extensions (2-byte length prefix + data)
        extensions_b64 = sct.get("extensions", "")
        extensions = base64.b64decode(extensions_b64) if extensions_b64 else b""
        parts.extend(struct.pack(">H", len(extensions)))
        parts.extend(extensions)

        # Signature: the CT log returns this as a base64 blob that
        # already contains hash_alg(1) + sig_alg(1) + sig_len(2) + sig.
        signature_b64 = sct.get("signature", "")
        if signature_b64:
            signature = base64.b64decode(signature_b64)
            parts.extend(signature)
        else:
            # No signature data — append minimal placeholder
            # (hash_alg=sha256=4, sig_alg=ecdsa=3, length=0)
            parts.extend(b"\x04\x03\x00\x00")

        sct_bytes = bytes(parts)

        # Each SCT is preceded by a 2-byte length
        serialized_scts.append(
            struct.pack(">H", len(sct_bytes)) + sct_bytes,
        )

    # Concatenate all serialised SCTs
    sct_list_body = b"".join(serialized_scts)

    # Outer 2-byte length prefix for the entire list
    return struct.pack(">H", len(sct_list_body)) + sct_list_body
