import sys

import pytest

from argus.cli import main


@pytest.mark.parametrize(
    ("arguments", "expected_text"),
    [
        (
            ["argus", "--help"],
            (
                "js",
                "report",
                "wordpress",
                "investigate",
                "--version",
            ),
        ),
        (
            ["argus", "js", "analyze", "--help"],
            (
                "--output",
                "--investigation",
                "--recursive",
                "JavaScript files",
            ),
        ),
        (
            ["argus", "investigate", "--help"],
            (
                "--analyst",
                "--target",
                "--profile",
                "--recursive",
                "--workspace-root",
                "local, authorized target",
            ),
        ),
    ],
)
def test_cli_help(
    arguments,
    expected_text,
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
        arguments,
    )

    with pytest.raises(SystemExit) as exc_info:
        main()

    assert exc_info.value.code == 0

    output = capsys.readouterr().out

    for text in expected_text:
        assert text in output
