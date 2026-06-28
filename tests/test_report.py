from argparse import Namespace

from argus.plugins import report


def test_report_missing_workspace(tmp_path):
    missing = tmp_path / "workspace"

    args = Namespace(path=str(missing))

    assert report.run(args) == 1
