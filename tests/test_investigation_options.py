import json
from argparse import Namespace

from argus.investigation.run import run


def test_custom_analyst_and_target(
    tmp_path,
    monkeypatch,
):
    monkeypatch.chdir(tmp_path)

    args = Namespace(
        analyst="Jonathan Mendiola",
        target="authorized-local-test",
        trace_enabled=False,
    )

    workspace = run(args)

    metadata = json.loads((workspace / "metadata.json").read_text(encoding="utf-8"))

    assert metadata["analyst"] == "Jonathan Mendiola"
    assert metadata["target"] == "authorized-local-test"
    assert metadata["trace_enabled"] is False


def test_trace_enabled_is_recorded(
    tmp_path,
    monkeypatch,
):
    monkeypatch.chdir(tmp_path)

    args = Namespace(
        analyst="Jonathan Mendiola",
        target="authorized-local-test",
        trace_enabled=True,
    )

    workspace = run(args)

    metadata = json.loads((workspace / "metadata.json").read_text(encoding="utf-8"))

    assert metadata["analyst"] == "Jonathan Mendiola"
    assert metadata["target"] == "authorized-local-test"
    assert metadata["trace_enabled"] is True
