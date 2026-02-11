"""Audit log file cleanup utility.

Deletes rotated audit log files older than the configured retention period.
Called periodically by the cleanup worker when audit_retention is enabled.
"""

from __future__ import annotations

import logging
import time
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from acmeeh.config.settings import AuditRetentionSettings

log = logging.getLogger(__name__)


def cleanup_old_audit_logs(settings: AuditRetentionSettings, audit_file: str | None) -> int:
    """Delete rotated audit log files older than max_age_days.

    Looks for files matching ``{audit_file}.*`` (e.g. ``audit.log.1``,
    ``audit.log.2``, etc.) and deletes those older than the retention period.

    Returns the number of files deleted.
    """
    if not settings.enabled or not audit_file:
        return 0

    max_age_seconds = settings.max_age_days * 86400
    cutoff = time.time() - max_age_seconds
    deleted = 0
    audit_path = Path(audit_file)
    parent = audit_path.parent

    if not parent.exists():
        return 0

    # Match rotated files: audit.log.1, audit.log.2, etc.
    pattern = audit_path.name + ".*"
    for path in parent.glob(pattern):
        try:
            if path.stat().st_mtime < cutoff:
                path.unlink()
                deleted += 1
                log.info("Deleted old audit log file: %s", path)
        except OSError as exc:
            log.warning("Failed to delete audit log file %s: %s", path, exc)

    if deleted > 0:
        log.info("Audit log cleanup: deleted %d old files", deleted)
    return deleted
