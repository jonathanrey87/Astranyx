import sys

import pytest

from argus import __version__
from argus.cli import main


def test_cli_version(
    monkeypatch,
    capsys,
):
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
        ["argus", "--version"],
    )

    with pytest.raises(SystemExit) as exc_info:
        main()

    assert exc_info.value.code == 0
    assert capsys.readouterr().out.strip() == (f"argus {__version__}")
