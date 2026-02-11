"""In-process metrics collector.

Collects counters and gauges without external dependencies.
Exports in OpenMetrics/Prometheus text format.
"""

from __future__ import annotations

import threading
import time


class MetricsCollector:
    """Thread-safe in-process metrics collector."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._counters: dict[str, int] = {}
        self._start_time = time.time()

    def increment(self, name: str, amount: int = 1, labels: dict | None = None) -> None:
        """Increment a counter."""
        key = self._make_key(name, labels)
        with self._lock:
            self._counters[key] = self._counters.get(key, 0) + amount

    def get(self, name: str, labels: dict | None = None) -> int:
        """Get the current value of a counter."""
        key = self._make_key(name, labels)
        with self._lock:
            return self._counters.get(key, 0)

    def export(self) -> str:
        """Export all metrics in Prometheus text format."""
        lines = []
        lines.append("# HELP acmeeh_uptime_seconds Time since process start")
        lines.append("# TYPE acmeeh_uptime_seconds gauge")
        lines.append(f"acmeeh_uptime_seconds {time.time() - self._start_time:.1f}")
        lines.append("")

        with self._lock:
            # Group by metric name
            grouped: dict[str, list[tuple[str, int]]] = {}
            for key, value in sorted(self._counters.items()):
                name = key.split("{")[0] if "{" in key else key
                grouped.setdefault(name, []).append((key, value))

            for name, entries in sorted(grouped.items()):
                lines.append(f"# TYPE {name} counter")
                for key, value in entries:
                    lines.append(f"{key} {value}")
                lines.append("")

        return "\n".join(lines) + "\n"

    @staticmethod
    def _make_key(name: str, labels: dict | None) -> str:
        if not labels:
            return name
        label_str = ",".join(f'{k}="{v}"' for k, v in sorted(labels.items()))
        return f"{name}{{{label_str}}}"
