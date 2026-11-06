from pathlib import Path

from astranyx.source import SourceReadError, read_source_text


def source_preview(file_path, line_number, radius=5, *, root=None, relative=None):
    """
    Return a list of (line_number, text) tuples around the requested line.
    """

    # A caller-supplied root is required to establish a trusted boundary.
    # Do not fall back to reading a potentially untrusted full_path.
    if root is None or relative is None:
        return []

    try:
        lines = read_source_text(Path(root), Path(root) / relative).splitlines()
    except (OSError, SourceReadError):
        return []

    start = max(1, line_number - radius)
    end = min(len(lines), line_number + radius)

    preview = []

    for i in range(start, end + 1):
        preview.append((i, lines[i - 1]))

    return preview
