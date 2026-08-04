import json

from argus.investigation.run import run
from argus.modules.js import analyze


def test_js_analysis_updates_investigation(
    tmp_path,
    monkeypatch,
):
    monkeypatch.chdir(tmp_path)

    run(None)

    workspaces = list((tmp_path / "investigations").glob("INV-*"))
    assert len(workspaces) == 1

    workspace = workspaces[0]

    source = tmp_path / "javascript"
    source.mkdir()

    bundle = source / "app.js"
    bundle.write_text(
        """
        fetch("/api/profile");
        const token = "test-placeholder";
        """,
        encoding="utf-8",
    )

    output = workspace / "analysis" / "javascript.json"

    report = analyze(
        source,
        output=output,
        investigation=workspace,
    )

    assert report["files_analyzed"] == 1
    assert report["routes"] == ["/api/profile"]
    assert output.is_file()

    metadata = json.loads((workspace / "metadata.json").read_text())

    assert metadata["target"] == str(source)
    assert len(metadata["modules"]) == 1

    module = metadata["modules"][0]

    assert module["name"] == "javascript"
    assert module["status"] == "completed"
    assert module["files"] == 1
    assert module["files_processed"] == 1
    assert module["files_failed"] == 0
    assert module["routes"] == 1
    assert module["output_report"] == str(output)
