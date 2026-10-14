"""Regression tests for the Astranyx AI demo CLI."""

import json
import sys

from astranyx.cli import main


def test_ai_demo_cli_generates_reports(tmp_path, monkeypatch):
    output = tmp_path / "reports"

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "astranyx",
            "ai-demo",
            "--output",
            str(output),
        ],
    )

    main()

    json_file = output / "ai-investigation.json"
    html_file = output / "ai-investigation.html"

    assert json_file.is_file()
    assert html_file.is_file()

    report = json.loads(json_file.read_text(encoding="utf-8"))

    assert report["report_type"] == "astranyx_ai_investigation"
    assert report["verification_status"] == "unverified"
    assert report["errors"] == []

    investigation = report["investigations"][0]

    assert investigation["ai_verified"] is False
    assert investigation["requires_validation"] is True

    html = html_file.read_text(encoding="utf-8")
    assert "UNVERIFIED" in html
