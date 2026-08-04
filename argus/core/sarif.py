import json
from pathlib import Path

SARIF_VERSION = "2.1.0"


def finding_to_result(finding):
    level = "note"

    sev = finding.severity.lower()

    if sev == "critical" or sev == "high":
        level = "error"
    elif sev == "medium":
        level = "warning"

    return {
        "ruleId": finding.category.replace(" ", "_"),
        "level": level,
        "message": {"text": finding.reason or finding.note or finding.category},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": finding.file},
                    "region": {"startLine": finding.line},
                }
            }
        ],
    }


def export(report, output_dir):
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    sarif = {
        "version": SARIF_VERSION,
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Argus",
                        "version": "1.2.0",
                        "informationUri": "https://github.com/ArgusSecurity/Argus",
                    }
                },
                "results": [finding_to_result(f) for f in report.findings],
            }
        ],
    }

    with (output_dir / "findings.sarif").open("w") as fp:
        json.dump(sarif, fp, indent=2)
