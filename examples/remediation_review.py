"""Generate a synthetic, offline README demo: python -m examples.remediation_review."""

import json
from pathlib import Path

from astranyx.comparison.retest import write_report


def main():
    output = Path("/tmp/astranyx-remediation-demo")
    output.mkdir(exist_ok=True)
    findings = [
        {
            "fingerprint": "asx-demo-config",
            "category": "Sensitive configuration in logs",
            "file": "src/settings.py",
            "line": 42,
            "severity": "Medium",
            "confidence": 70,
            "evidence": "Synthetic example: diagnostic output includes configuration values.",
            "reason": "Review logging fields and redact sensitive values before release.",
        },
        {
            "fingerprint": "asx-demo-cookie",
            "category": "Session cookie configuration",
            "file": "src/session.py",
            "line": 18,
            "severity": "Low",
            "confidence": 75,
            "evidence": "Synthetic example: session cookie settings need review.",
            "reason": "Verify cookie protections against the application's deployment requirements.",
        },
        {
            "fingerprint": "asx-demo-debug",
            "category": "Debug output enabled",
            "file": "config/app.py",
            "line": 9,
            "severity": "Low",
            "confidence": 80,
            "evidence": "Synthetic example: debug output configured in the baseline.",
            "reason": "Confirm production configuration and equivalent scan coverage.",
        },
    ]
    current = [
        dict(findings[0], severity="High", confidence=90),
        findings[1],
        {
            "fingerprint": "asx-demo-errors",
            "category": "Verbose error details",
            "file": "src/errors.py",
            "line": 27,
            "severity": "Medium",
            "confidence": 80,
            "evidence": "Synthetic example: error rendering includes internal details.",
            "reason": "Return a generic error to users and retain details in protected logs.",
        },
    ]
    for name, entries in (("baseline", findings), ("current", current)):
        (output / f"{name}.json").write_text(
            json.dumps({"schema_version": 1, "findings": entries}), encoding="utf-8"
        )
    result = write_report(
        output / "baseline.json", output / "current.json", output / "review"
    )
    print(result["output_directory"])


if __name__ == "__main__":
    main()
