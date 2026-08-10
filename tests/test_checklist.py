from astranyx.services.checklist import create


def test_checklist_created(tmp_path):
    workspace = tmp_path / "INV_Test"
    workspace.mkdir()

    checklist = create(workspace)

    assert checklist.exists()
    assert checklist.name == "checklist.md"
    assert "Investigation Checklist" in checklist.read_text()
