"""Audit webhook hook for real-time event streaming to SIEM."""

from __future__ import annotations

import json
import logging
from typing import Any

from acmeeh.hooks.base import Hook

log = logging.getLogger(__name__)


class AuditWebhookHook(Hook):
    """Streams audit events to a webhook URL."""

    def __init__(self, config: dict) -> None:
        self._url = config.get("webhook_url", "")
        self._timeout = config.get("timeout_seconds", 10)

    def _send(self, event: str, data: dict[str, Any]) -> None:
        if not self._url:
            return
        try:
            import urllib.request

            payload = json.dumps({"event": event, "data": data}).encode("utf-8")
            req = urllib.request.Request(
                self._url,
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            urllib.request.urlopen(req, timeout=self._timeout)
        except Exception:
            log.exception("Failed to send audit webhook for event %s", event)

    def on_certificate_issuance(self, data: dict[str, Any]) -> None:
        self._send("certificate.issuance", data)

    def on_certificate_revocation(self, data: dict[str, Any]) -> None:
        self._send("certificate.revocation", data)

    def on_account_registration(self, data: dict[str, Any]) -> None:
        self._send("account.registration", data)
