import json
import sys

from argus.cli import main


def test_recursive_javascript_cli(
    tmp_path,
    monkeypatch,
):
    nested = tmp_path / "assets" / "js"
    nested.mkdir(parents=True)

    bundle = nested / "app.js"
    bundle.write_text(
        'fetch("/api/nested");',
        encoding="utf-8",
    )

    report_path = tmp_path / "report.json"

    monkeypatch.delenv(
        "ARIZE_SPACE_ID",
        raising=False,
    )
    monkeypatch.delenv(
        "ARIZE_API_KEY",
        raising=False,
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "argus",
            "js",
            "analyze",
            str(tmp_path),
            "--recursive",
            "--output",
            str(report_path),
        ],
    )

    main()

    assert report_path.is_file()

    report = json.loads(report_path.read_text(encoding="utf-8"))

    assert report["files_analyzed"] == 1
    assert report["routes"] == ["/api/nested"]
    assert report["summary"] == {
        "assets/js/app.js": {
            "network_fetch": 1,
        }
    }
