import hashlib
import json
import os

import pytest

from astranyx.investigation import integrity


def write_manifest(workspace, artifacts):
    (workspace / "manifest.json").write_text(
        json.dumps(
            {
                "investigation": {"id": "INV-TEST"},
                "artifacts": artifacts,
            }
        )
    )


def record(path, workspace):
    content = path.read_bytes()
    return {
        "path": path.relative_to(workspace).as_posix(),
        "size_bytes": len(content),
        "sha256": hashlib.sha256(content).hexdigest(),
    }


def test_verify_accepts_intact_investigation(tmp_path):
    artifact = tmp_path / "reports" / "report.json"
    artifact.parent.mkdir()
    artifact.write_text('{"finding": "validated"}')
    write_manifest(tmp_path, [record(artifact, tmp_path)])

    result = integrity.verify(tmp_path)

    assert result["valid"] is True
    assert result["investigation_id"] == "INV-TEST"
    assert result["artifacts_checked"] == 1
    assert result["failures"] == []


def test_verify_reports_modified_and_missing_artifacts(tmp_path):
    modified = tmp_path / "modified.txt"
    modified.write_text("original")
    records = [
        record(modified, tmp_path),
        {
            "path": "missing.txt",
            "size_bytes": 1,
            "sha256": "0" * 64,
        },
    ]
    write_manifest(tmp_path, records)
    modified.write_text("changed")

    result = integrity.verify(tmp_path)

    assert result["valid"] is False
    reasons = [failure["reason"] for failure in result["failures"]]
    assert "size mismatch" in reasons
    assert "SHA-256 mismatch" in reasons
    assert any(reason.startswith("unreadable:") for reason in reasons)


def test_verify_rejects_unsafe_and_duplicate_paths(tmp_path):
    artifact = tmp_path / "artifact.txt"
    artifact.write_text("evidence")
    artifact_record = record(artifact, tmp_path)
    write_manifest(
        tmp_path,
        [artifact_record, artifact_record, {"path": "../outside", "size_bytes": 0}],
    )

    result = integrity.verify(tmp_path)

    assert result["valid"] is False
    assert [failure["reason"] for failure in result["failures"]] == [
        "duplicate artifact path",
        "unsafe artifact path",
    ]


def test_verify_rejects_internal_symlink_artifact(tmp_path):
    """An evidence artifact must not be a symlink alias."""
    original = tmp_path / "original.txt"
    original.write_text("evidence")

    alias = tmp_path / "alias.txt"
    alias.symlink_to(original)

    write_manifest(
        tmp_path,
        [
            {
                "path": "alias.txt",
                "size_bytes": len(original.read_bytes()),
                "sha256": hashlib.sha256(original.read_bytes()).hexdigest(),
            }
        ],
    )

    result = integrity.verify(tmp_path)

    assert result["valid"] is False
    assert any(
        failure["reason"] == "unsafe artifact path" for failure in result["failures"]
    )


@pytest.mark.skipif(os.name != "posix", reason="POSIX dir_fd protections")
def test_verify_rejects_final_symlink_swapped_after_path_validation(tmp_path, monkeypatch):
    artifact = tmp_path / "artifact.txt"
    artifact.write_bytes(b"expected")
    outside = tmp_path.parent / (tmp_path.name + "-outside.txt")
    outside.write_bytes(b"expected")
    write_manifest(tmp_path, [record(artifact, tmp_path)])

    real_open = integrity.os.open
    swapped = False

    def swap_then_open(path, flags, *args, **kwargs):
        nonlocal swapped
        if path == "artifact.txt" and not swapped:
            swapped = True
            artifact.unlink()
            artifact.symlink_to(outside)
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(integrity.os, "open", swap_then_open)
    try:
        result = integrity.verify(tmp_path)
    finally:
        artifact.unlink(missing_ok=True)
        outside.unlink(missing_ok=True)

    assert swapped
    assert result["valid"] is False
    assert result["artifacts_checked"] == 0
    assert result["failures"][0]["reason"].startswith("unreadable:")


@pytest.mark.skipif(os.name != "posix", reason="POSIX dir_fd protections")
def test_verify_rejects_intermediate_directory_swapped_to_symlink(tmp_path, monkeypatch):
    reports = tmp_path / "reports"
    reports.mkdir()
    artifact = reports / "artifact.txt"
    artifact.write_bytes(b"evidence")
    outside = tmp_path.parent / (tmp_path.name + "-outside-dir")
    outside.mkdir()
    (outside / "artifact.txt").write_bytes(b"evidence")
    write_manifest(tmp_path, [record(artifact, tmp_path)])

    real_open = integrity.os.open
    swapped = False

    def swap_then_open(path, flags, *args, **kwargs):
        nonlocal swapped
        if path == "reports" and not swapped:
            swapped = True
            reports.rename(tmp_path / "reports-original")
            reports.symlink_to(outside, target_is_directory=True)
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(integrity.os, "open", swap_then_open)
    try:
        result = integrity.verify(tmp_path)
    finally:
        (tmp_path / "reports").unlink(missing_ok=True)
        for p in outside.iterdir():
            p.unlink()
        outside.rmdir()

    assert swapped
    assert result["valid"] is False
    assert result["artifacts_checked"] == 0
    assert result["failures"][0]["reason"].startswith("unreadable:")
