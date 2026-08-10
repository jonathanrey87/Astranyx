"""Small OpenTelemetry compatibility layer used by Argus modules.

Argus records spans when OpenTelemetry is installed. Static analysis and the
command-line interface remain usable without the optional tracing stack.
"""

from __future__ import annotations

from contextlib import nullcontext
from enum import Enum
from typing import Any

try:
    from opentelemetry import trace
    from opentelemetry.trace import Status, StatusCode
except ImportError:

    class StatusCode(Enum):
        """Fallback values matching the OpenTelemetry status names."""

        UNSET = 0
        OK = 1
        ERROR = 2

    class Status:
        """Fallback span status used when OpenTelemetry is unavailable."""

        def __init__(
            self,
            status_code: StatusCode = StatusCode.UNSET,
            description: str | None = None,
        ) -> None:
            self.status_code = status_code
            self.description = description

    class _NoOpSpan:
        def set_attribute(self, _name: str, _value: Any) -> None:
            return None

        def set_status(self, _status: Status) -> None:
            return None

        def record_exception(self, _exception: BaseException) -> None:
            return None

    class _NoOpTracer:
        def start_as_current_span(self, _name: str):
            return nullcontext(_NoOpSpan())

    class _NoOpTrace:
        @staticmethod
        def get_tracer(_name: str) -> _NoOpTracer:
            return _NoOpTracer()

    trace = _NoOpTrace()
