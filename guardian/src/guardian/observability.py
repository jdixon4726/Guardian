"""
Guardian Observability — Metrics and Structured Logging

Provides:
  - In-process metrics counters (no external dependency)
  - /metrics endpoint compatible with Prometheus text format
  - Structured JSON log formatter
  - Request timing middleware

Production deployments should add prometheus_client or opentelemetry
for full histogram support. This module provides baseline observability
with zero additional dependencies.
"""

from __future__ import annotations

import json
import logging
import threading
import time
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware


# ── Metrics Store ────────────────────────────────────────────────────────────

class MetricsStore:
    """Thread-safe in-process metrics counters."""

    def __init__(self):
        self._counters: dict[str, int] = defaultdict(int)
        self._gauges: dict[str, float] = {}
        self._histograms: dict[str, list[float]] = defaultdict(list)
        self._lock = threading.Lock()

    def inc(self, name: str, value: int = 1) -> None:
        with self._lock:
            self._counters[name] += value

    def gauge(self, name: str, value: float) -> None:
        with self._lock:
            self._gauges[name] = value

    def observe(self, name: str, value: float) -> None:
        with self._lock:
            hist = self._histograms[name]
            hist.append(value)
            # Keep only last 1000 observations
            if len(hist) > 1000:
                self._histograms[name] = hist[-1000:]

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            result = {
                "counters": dict(self._counters),
                "gauges": dict(self._gauges),
            }
            for name, values in self._histograms.items():
                if values:
                    sorted_v = sorted(values)
                    n = len(sorted_v)
                    result.setdefault("histograms", {})[name] = {
                        "count": n,
                        "p50": sorted_v[int(n * 0.5)] if n else 0,
                        "p95": sorted_v[int(n * 0.95)] if n else 0,
                        "p99": sorted_v[int(n * 0.99)] if n else 0,
                        "max": sorted_v[-1] if n else 0,
                    }
            return result

    def prometheus_text(self) -> str:
        """Export metrics in Prometheus text exposition format."""
        lines = []
        with self._lock:
            for name, value in sorted(self._counters.items()):
                prom_name = name.replace(".", "_").replace("-", "_")
                lines.append(f"# TYPE {prom_name} counter")
                lines.append(f"{prom_name} {value}")
            for name, value in sorted(self._gauges.items()):
                prom_name = name.replace(".", "_").replace("-", "_")
                lines.append(f"# TYPE {prom_name} gauge")
                lines.append(f"{prom_name} {value}")
            for name, values in sorted(self._histograms.items()):
                if values:
                    prom_name = name.replace(".", "_").replace("-", "_")
                    sorted_v = sorted(values)
                    n = len(sorted_v)
                    lines.append(f"# TYPE {prom_name} summary")
                    lines.append(f'{prom_name}{{quantile="0.5"}} {sorted_v[int(n*0.5)]}')
                    lines.append(f'{prom_name}{{quantile="0.95"}} {sorted_v[int(n*0.95)]}')
                    lines.append(f'{prom_name}{{quantile="0.99"}} {sorted_v[int(n*0.99)]}')
                    lines.append(f"{prom_name}_count {n}")
                    lines.append(f"{prom_name}_sum {sum(values):.6f}")
        return "\n".join(lines) + "\n"


# Global metrics instance
metrics = MetricsStore()


# ── Structured JSON Logging ──────────────────────────────────────────────────

class StructuredJSONFormatter(logging.Formatter):
    """Format log records as JSON lines for SIEM/log aggregation."""

    def format(self, record: logging.LogRecord) -> str:
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info and record.exc_info[1]:
            entry["exception"] = str(record.exc_info[1])
        # Include extra fields
        for key in ("actor_name", "action", "risk_score", "decision",
                     "entry_id", "request_id", "adapter"):
            if hasattr(record, key):
                entry[key] = getattr(record, key)
        return json.dumps(entry, default=str)


def configure_structured_logging(json_mode: bool = True) -> None:
    """Configure root logger for structured JSON output."""
    root = logging.getLogger()
    if json_mode:
        handler = logging.StreamHandler()
        handler.setFormatter(StructuredJSONFormatter())
        root.handlers = [handler]
        root.setLevel(logging.INFO)


# ── Request Timing Middleware ────────────────────────────────────────────────

class MetricsMiddleware(BaseHTTPMiddleware):
    """FastAPI middleware that tracks request count and latency."""

    async def dispatch(self, request: Request, call_next) -> Response:
        start = time.monotonic()
        response = await call_next(request)
        duration = time.monotonic() - start

        path = request.url.path
        metrics.inc(f"guardian.http.requests.total")
        metrics.inc(f"guardian.http.status.{response.status_code}")
        metrics.observe("guardian.http.duration_seconds", duration)

        # Track evaluation-specific metrics
        if "/evaluate" in path:
            metrics.inc("guardian.evaluations.total")
            metrics.observe("guardian.evaluations.duration_seconds", duration)
        elif "/mcp/" in path:
            metrics.inc("guardian.mcp.evaluations.total")
        elif "/a2a/" in path:
            metrics.inc("guardian.a2a.evaluations.total")

        return response
