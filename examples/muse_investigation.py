"""Astranyx Muse Spark investigation demonstration."""

import argparse
import json

from astranyx.ai.investigator import AIInvestigator
from astranyx.ai.privacy import require_synthetic_finding
from astranyx.ai.provider import MuseProvider


class DemoProvider:
    def generate(self, prompt):
        return json.dumps({
            "summary": "Possible broken object-level authorization",
            "impact": "Cross-account exposure is possible but unverified",
            "next_step": (
                "Use two authorized test accounts and compare "
                "object ownership enforcement"
            ),
        })


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--live",
        action="store_true",
        help="Call Meta Muse Spark using synthetic evidence",
    )
    args = parser.parse_args()

    finding = {
        "category": "authorization",
        "severity": "high",
        "evidence": (
            "Synthetic lab: account B can retrieve account A's "
            "test invoice using a changed object identifier."
        ),
        "reason": "Potential missing ownership validation",
        "fingerprint": "asx-muse-demo-001",
        "data_classification": "synthetic",
    }

    safe_finding = require_synthetic_finding(finding)

    provider = MuseProvider() if args.live else DemoProvider()
    result = AIInvestigator(provider).analyze(safe_finding)

    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
