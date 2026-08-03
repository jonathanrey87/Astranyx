from datetime import datetime, timezone
from pathlib import Path
import json

from opentelemetry import trace
from opentelemetry.trace import Status, StatusCode

tracer = trace.get_tracer("argus.investigation")


def run(args):
    """Create a new Argus investigation workspace."""

    with tracer.start_as_current_span("argus.investigation.create") as span:
        timestamp = datetime.now(timezone.utc)

        investigation_id = timestamp.strftime("INV-%Y%m%d-%H%M%S")
        root = Path("investigations") / investigation_id

        directories = (
            "analysis",
            "api",
            "evidence",
            "html",
            "js",
            "logs",
            "notes",
            "reports",
            "screenshots",
        )

        try:
            for directory in directories:
                (root / directory).mkdir(parents=True, exist_ok=True)

            metadata = {
                "id": investigation_id,
                "created": timestamp.isoformat(),
                "status": "created",
                "target": None,
                "analyst": "Jonathan Mendiola",
                "argus_version": "3.0.0a1",
                "trace_enabled": True,
                "modules": [],
                "findings": {
                    "critical": 0,
                    "high": 0,
                    "medium": 0,
                    "low": 0,
                    "info": 0,
                },
            }

            metadata_path = root / "metadata.json"

            metadata_path.write_text(
                json.dumps(metadata, indent=2)
            )

            span.set_attribute(
                "argus.investigation.id",
                investigation_id,
            )

            span.set_attribute(
                "argus.metadata.file",
                str(metadata_path),
            )

            span.set_attribute(
                "argus.workspace.directories",
                len(directories),
            )

            span.set_status(Status(StatusCode.OK))

            print(f"[+] Investigation created")
            print(f"    ID: {investigation_id}")
            print(f"    Path: {root}")
            print(f"    Metadata: {metadata_path}")

        except Exception as exc:
            span.record_exception(exc)
            span.set_status(
                Status(StatusCode.ERROR, str(exc))
            )
            raise
