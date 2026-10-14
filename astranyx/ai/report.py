"""Export AI-assisted investigation results without changing finding schema v1."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


def build_ai_report(context: dict[str, Any]) -> dict[str, Any]:
    """Build a companion report from an executed investigation context."""
    investigations = context.get("ai_investigations", [])
    errors = context.get("ai_investigation_errors", [])

    if not isinstance(investigations, list):
        raise TypeError("ai_investigations must be a list")
    if not isinstance(errors, list):
        raise TypeError("ai_investigation_errors must be a list")

    entries = []
    for item in investigations:
        if not isinstance(item, dict):
            raise TypeError("AI investigation entries must be dictionaries")

        entries.append(
            {
                "finding_fingerprint": str(item.get("finding_fingerprint", "")),
                "summary": str(item.get("summary", "")),
                "impact": str(item.get("impact", "")),
                "next_step": str(item.get("next_step", "")),
                "ai_verified": False,
                "requires_validation": True,
            }
        )

    return {
        "report_type": "astranyx_ai_investigation",
        "schema_version": 1,
        "generated": datetime.now(UTC).isoformat(),
        "verification_status": "unverified",
        "investigations": entries,
        "errors": [
            {
                "index": error.get("index"),
                "type": str(error.get("type", "unknown")),
            }
            for error in errors
            if isinstance(error, dict)
        ],
    }


def write_ai_json(report: dict[str, Any], path: str | Path) -> Path:
    """Write the AI companion report as UTF-8 JSON."""
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(report, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return output


def write_ai_html(report: dict[str, Any], path: str | Path) -> Path:
    """Write a standalone HTML investigation dashboard."""
    from astranyx.ai.dashboard import render_dashboard

    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(render_dashboard(report), encoding="utf-8")
    return output
