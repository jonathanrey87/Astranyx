from argparse import Namespace

from astranyx.plugins import review


def test_review_missing_workspace_returns_error(tmp_path):
    missing = tmp_path / "missing_workspace"
    args = Namespace(path=str(missing))

    result = review.run(args)

    assert result == 1
