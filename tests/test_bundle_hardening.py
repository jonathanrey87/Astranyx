from astranyx.evidence import bundle


def test_safe_child_rejects_intermediate_symlink(tmp_path):
    outside = tmp_path.parent / f"{tmp_path.name}-outside"
    outside.mkdir()

    (outside / "evidence.txt").write_text("secret")

    (tmp_path / "linked").symlink_to(
        outside,
        target_is_directory=True,
    )

    try:
        bundle._safe_child(tmp_path, "linked/evidence.txt")
    except bundle.EvidenceError:
        return

    raise AssertionError("Intermediate directory symlink was accepted")


def test_safe_child_rejects_parent_traversal(tmp_path):
    try:
        bundle._safe_child(tmp_path, "../outside.txt")
    except bundle.EvidenceError:
        return

    raise AssertionError("Parent directory traversal was accepted")
