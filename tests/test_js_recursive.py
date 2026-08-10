import pytest

from astranyx.modules.js import analyze


def test_nested_javascript_requires_recursive(
    tmp_path,
):
    nested = tmp_path / "assets" / "js"
    nested.mkdir(parents=True)

    bundle = nested / "app.js"
    bundle.write_text(
        'fetch("/api/nested");',
        encoding="utf-8",
    )

    with pytest.raises(
        SystemExit,
        match="No JavaScript files found",
    ):
        analyze(tmp_path)

    report = analyze(
        tmp_path,
        recursive=True,
    )

    assert report["files_analyzed"] == 1
    assert report["routes"] == ["/api/nested"]
    assert "assets/js/app.js" in report["summary"]
