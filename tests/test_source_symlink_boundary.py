from astranyx.core.preview import source_preview
from astranyx.modules.js import analyze
from astranyx.wordpress import scanner

SENTINEL = "ASTRANYX_OUTSIDE_SOURCE_SENTINEL"


def test_wordpress_report_does_not_follow_javascript_file_symlink(tmp_path):
    outside = tmp_path / "outside.js"
    outside.write_text(
        f'element.innerHTML = "{SENTINEL}";',
        encoding="utf-8",
    )
    plugin = tmp_path / "plugin"
    plugin.mkdir()
    (plugin / "linked.js").symlink_to(outside)
    output = tmp_path / "report"

    result = scanner.run(plugin, output=output)

    assert result["findings_total"] == 0
    for artifact in output.iterdir():
        if artifact.is_file():
            assert SENTINEL not in artifact.read_text(encoding="utf-8")


def test_wordpress_scanner_skips_php_file_symlink_without_crashing(tmp_path):
    outside = tmp_path / "outside.php"
    outside.write_text(
        f'<?php eval("{SENTINEL}");',
        encoding="utf-8",
    )
    plugin = tmp_path / "plugin"
    plugin.mkdir()
    (plugin / "linked.php").symlink_to(outside)

    assert scanner.scan_plugin(plugin) == []
    assert scanner.scan_plugin(plugin, recursive=False) == []


def test_wordpress_scanner_does_not_descend_into_symlink_directory(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.js").write_text(
        f'element.innerHTML = "{SENTINEL}";',
        encoding="utf-8",
    )
    plugin = tmp_path / "plugin"
    plugin.mkdir()
    (plugin / "linked").symlink_to(outside, target_is_directory=True)

    assert scanner.scan_plugin(plugin) == []


def test_javascript_analyzer_skips_symlinked_source(tmp_path):
    outside = tmp_path / "outside.js"
    outside.write_text(f'fetch("/{SENTINEL}");', encoding="utf-8")
    target = tmp_path / "target"
    target.mkdir()
    (target / "linked.js").symlink_to(outside)
    output = tmp_path / "javascript.json"

    result = analyze(target, output=output)

    assert result["files_analyzed"] == 0
    assert SENTINEL not in output.read_text(encoding="utf-8")


def test_javascript_analyzer_accepts_symlinked_scan_root(tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    (target / "app.js").write_text('fetch("/ordinary");', encoding="utf-8")
    alias = tmp_path / "target-alias"
    alias.symlink_to(target, target_is_directory=True)

    result = analyze(alias)

    assert result["files_analyzed"] == 1
    assert result["routes"] == ["/ordinary"]


def test_ordinary_source_files_remain_analyzable(tmp_path):
    plugin = tmp_path / "plugin"
    plugin.mkdir()
    (plugin / "plugin.php").write_text(
        "<?php add_action('wp_ajax_nopriv_demo', 'demo');",
        encoding="utf-8",
    )
    (plugin / "app.js").write_text(
        'element.innerHTML = "safe";',
        encoding="utf-8",
    )

    findings = scanner.scan_plugin(plugin)
    javascript = analyze(plugin, recursive=True)

    assert {finding.category for finding in findings} >= {
        "Public AJAX Route",
        "DOM Sink",
    }
    assert javascript["files_analyzed"] == 1
    assert javascript["source_files"][0]["path"] == "app.js"


def test_source_preview_requires_explicit_analysis_root(tmp_path):
    outside = tmp_path / "outside.txt"
    outside.write_text("PRIVATE_OUTSIDE_SOURCE", encoding="utf-8")

    assert source_preview(outside, 1) == []
    assert source_preview(outside, 1, root=tmp_path, relative=None) == []


def test_source_preview_rejects_symlink_within_root(tmp_path):
    source_root = tmp_path / "source"
    source_root.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("PRIVATE_OUTSIDE_SOURCE", encoding="utf-8")
    (source_root / "linked.txt").symlink_to(outside)

    assert (
        source_preview(
            source_root / "linked.txt",
            1,
            root=source_root,
            relative="linked.txt",
        )
        == []
    )


def test_source_preview_reads_regular_file_inside_root(tmp_path):
    source = tmp_path / "regular.txt"
    source.write_text("first\\nsecond\\nthird\\n", encoding="utf-8")

    preview = source_preview(
        source, 2, radius=0, root=tmp_path, relative="regular.txt"
    )
    assert preview == [(2, "second")]
