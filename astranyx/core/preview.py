from pathlib import Path

from astranyx.source import SourceReadError, read_source_text


def source_preview(file_path, line_number, radius=5, *, root=None, relative=None):
    """
    Return a list of (line_number, text) tuples around the requested line.
    """

    try:
        if root is not None and relative is not None:
            lines = read_source_text(Path(root), Path(root) / relative).splitlines()
        else:
            path = Path(file_path)
            if not path.exists():
                return []
            lines = path.read_text(errors="ignore").splitlines()
    except (OSError, SourceReadError):
        return []

    start = max(1, line_number - radius)
    end = min(len(lines), line_number + radius)

    preview = []

    for i in range(start, end + 1):
        preview.append((i, lines[i - 1]))

    return preview
