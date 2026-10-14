
"""Astranyx end-to-end AI investigation demonstration."""

import argparse
import json
from pathlib import Path

from astranyx.ai.provider import MuseProvider
from astranyx.ai.report import (
    build_ai_report,
    write_ai_html,
    write_ai_json,
)
from astranyx.analysis.pipeline import build_default_pipeline


class DemoProvider:
    """Offline provider returning fabricated investigation analysis."""

    def generate(self, prompt):
        return json.dumps(
            {
                "summary": "Possible broken object-level authorization",
                "impact": (
                    "Cross-account exposure is possible "
                    "but remains unverified"
                ),
                "next_step": (
                    "Use two authorized test accounts to "
                    "validate object ownership enforcement"
                ),
            }
        )


def main():
    parser = argparse.ArgumentParser(
        description="Astranyx AI investigation demonstration"
    )
    parser.add_argument(
        "--live",
        action="store_true",
        help="Use Meta Muse Spark with synthetic evidence",
    )
    parser.add_argument(
        "--output",
        default="demo-output",
        help="Directory for generated reports",
    )
    args = parser.parse_args()

    finding = {
        "category": "authorization",
        "severity": "high",
        "evidence": (
            "Synthetic lab: account B retrieves account A's "
            "test invoice using a modified object identifier."
        ),
        "reason": "Potential missing ownership validation",
        "fingerprint": "asx-muse-demo-001",
        "data_classification": "synthetic",
    }

    provider = MuseProvider() if args.live else DemoProvider()

    pipeline = build_default_pipeline(
        enable_ai=True,
        provider=provider,
    )

    context = {
        "finding_evidence": [],
        "ai_findings": [finding],
    }

    result = pipeline.execute(context)
    report = build_ai_report(result)

    output_dir = Path(args.output)
    json_path = write_ai_json(
        report,
        output_dir / "ai-investigation.json",
    )
    html_path = write_ai_html(
        report,
        output_dir / "ai-investigation.html",
    )

    print(json.dumps(report, indent=2))
    print(f"\nJSON report: {json_path}")
    print(f"HTML report: {html_path}")

    if report["errors"]:
        raise SystemExit("AI investigation completed with errors")

def run_demo(*, output="demo-output", live=False):
    import sys

    previous = sys.argv
    try:
        sys.argv = ["muse_investigation", "--output", output]
        if live:
            sys.argv.append("--live")
        main()
    finally:
        sys.argv = previous
if __name__ == "__main__":
    main()
