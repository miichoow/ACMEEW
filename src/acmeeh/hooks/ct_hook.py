"""CT (Certificate Transparency) submission hook.

Submits issued certificates to configured CT logs per RFC 6962.
"""

from __future__ import annotations

import contextlib
import json
import logging
import urllib.error
import urllib.request

from acmeeh.hooks.base import Hook

log = logging.getLogger(__name__)


class CTSubmissionHook(Hook):
    """Submits certificates to CT logs on issuance."""

    @classmethod
    def validate_config(cls, config: dict) -> None:
        logs = config.get("logs", [])
        if not isinstance(logs, list):
            msg = "CT hook 'logs' must be a list"
            raise ValueError(msg)
        for i, entry in enumerate(logs):
            if not isinstance(entry, dict) or not entry.get("url"):
                msg = f"CT hook logs[{i}] must have a 'url'"
                raise ValueError(msg)

    def on_certificate_issuance(self, ctx: dict) -> None:
        """Submit the certificate chain to each configured CT log."""
        pem_chain = ctx.get("pem_chain")
        if not pem_chain:
            log.warning("CT hook: no pem_chain in context, skipping")
            return

        logs = self.config.get("logs", [])
        for ct_log in logs:
            try:
                self._submit_to_log(ct_log, pem_chain, ctx)
            except Exception:
                log.exception(
                    "CT submission failed for %s (serial=%s)",
                    ct_log.get("url", "?"),
                    ctx.get("serial_number", "?"),
                )

    def _submit_to_log(
        self,
        ct_log: dict,
        pem_chain: str,
        ctx: dict,
    ) -> dict | None:
        """Submit a chain to a single CT log."""
        url = ct_log["url"].rstrip("/") + "/ct/v1/add-chain"
        timeout = ct_log.get("timeout_seconds", 10)

        # Split PEM chain into individual certs and base64-encode DER
        chain_b64 = []
        for pem_block in pem_chain.split("-----END CERTIFICATE-----"):
            pem_block = pem_block.strip()
            if not pem_block:
                continue
            # Extract base64 content between BEGIN and END markers
            lines = pem_block.split("\n")
            b64_lines = [line for line in lines if line and not line.startswith("-----")]
            if b64_lines:
                der_b64 = "".join(b64_lines)
                chain_b64.append(der_b64)

        payload = json.dumps({"chain": chain_b64}).encode("utf-8")

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
                "CT submission succeeded: log=%s serial=%s sct_version=%s",
                ct_log["url"],
                ctx.get("serial_number", "?"),
                sct.get("sct_version", "?"),
            )
            return sct
        except urllib.error.HTTPError as exc:
            body = ""
            with contextlib.suppress(Exception):
                body = exc.read().decode("utf-8", errors="replace")[:200]
            log.exception(
                "CT log %s returned HTTP %d: %s",
                ct_log["url"],
                exc.code,
                body,
            )
            raise
        except Exception as exc:
            log.exception("CT submission to %s failed: %s", ct_log["url"], exc)
            raise
