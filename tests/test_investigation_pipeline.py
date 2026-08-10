import hashlib
import json
import sys

import pytest

from argus.cli import main
from argus.investigation import orchestrator


def _write_web_target(root):
    target = root / "authorized-target"
    assets = target / "assets"
    assets.mkdir(parents=True)

    (assets / "app.js").write_text(
        'fetch("/api/profile");',
        encoding="utf-8",
    )
    (target / "plugin.php").write_text(
        "<?php add_action('wp_ajax_nopriv_demo', 'demo');",
        encoding="utf-8",
    )
    return target


def test_select_modules_for_web_target(tmp_path):
    target = _write_web_target(tmp_path)

    assert orchestrator.select_modules(target, "auto") == [
        "javascript",
        "wordpress",
    ]
    assert orchestrator.select_modules(target, "javascript") == ["javascript"]
    assert orchestrator.select_modules(target, "wordpress") == ["wordpress"]

    with pytest.raises(ValueError, match="No analyzable"):
        orchestrator.select_modules(
            target,
            "javascript",
            recursive=False,
        )


def test_select_modules_rejects_empty_target(tmp_path):
    target = tmp_path / "empty"
    target.mkdir()

    with pytest.raises(ValueError, match="No analyzable"):
        orchestrator.select_modules(target)


def test_investigation_pipeline_generates_hashed_manifest(tmp_path):
    target = _write_web_target(tmp_path)
    workspace_root = tmp_path / "investigations"

    result = orchestrator.run(
        target,
        profile="web",
        workspace_root=workspace_root,
    )

    workspace = result["workspace"]
    metadata = json.loads((workspace / "metadata.json").read_text())
    manifest = json.loads((workspace / "manifest.json").read_text())

    assert result["status"] == "completed"
    assert metadata["status"] == "completed"
    assert metadata["profile"] == "web"
    assert metadata["selected_modules"] == ["javascript", "wordpress"]
    assert [module["name"] for module in metadata["modules"]] == [
        "javascript",
        "wordpress",
    ]
    assert (workspace / "analysis" / "javascript.json").is_file()
    assert (workspace / "reports" / "wordpress" / "index.html").is_file()
    assert manifest["investigation"]["status"] == "completed"
    assert manifest["failures"] == []

    for artifact in manifest["artifacts"]:
        artifact_path = workspace / artifact["path"]
        digest = hashlib.sha256(artifact_path.read_bytes()).hexdigest()
        assert artifact["sha256"] == digest


def test_investigation_pipeline_isolates_module_failure(
    tmp_path,
    monkeypatch,
):
    target = _write_web_target(tmp_path)

    def fail_wordpress(*_args, **_kwargs):
        raise RuntimeError("test analyzer failure")

    monkeypatch.setattr(
        orchestrator,
        "_run_wordpress",
        fail_wordpress,
    )

    result = orchestrator.run(
        target,
        profile="web",
        workspace_root=tmp_path / "investigations",
    )

    metadata = json.loads(
        (result["workspace"] / "metadata.json").read_text(encoding="utf-8")
    )

    assert result["status"] == "partial"
    assert result["failures"] == [
        {
            "module": "wordpress",
            "error_type": "RuntimeError",
            "message": "test analyzer failure",
        }
    ]
    assert metadata["status"] == "partial"
    assert metadata["modules"][-1]["status"] == "failed"


def test_investigate_cli_runs_target_pipeline(
    tmp_path,
    monkeypatch,
):
    target = _write_web_target(tmp_path)
    workspace_root = tmp_path / "cli-investigations"

    monkeypatch.delenv("ARIZE_SPACE_ID", raising=False)
    monkeypatch.delenv("ARIZE_API_KEY", raising=False)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "argus",
            "investigate",
            str(target),
            "--profile",
            "javascript",
            "--workspace-root",
            str(workspace_root),
        ],
    )

    main()

    workspaces = list(workspace_root.glob("INV-*"))
    assert len(workspaces) == 1

    metadata = json.loads((workspaces[0] / "metadata.json").read_text(encoding="utf-8"))
    assert metadata["status"] == "completed"
    assert metadata["selected_modules"] == ["javascript"]
