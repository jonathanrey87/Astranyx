from argus.services.status import get_status


def test_empty_workspace_returns_do_not_submit(tmp_path):
    workspace = tmp_path / "INV_Test"
    workspace.mkdir()

    assert get_status(workspace) == "DO NOT SUBMIT"
