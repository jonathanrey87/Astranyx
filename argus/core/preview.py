from pathlib import Path


def source_preview(file_path, line_number, radius=5):
    """
    Return a list of (line_number, text) tuples around the requested line.
    """

    path = Path(file_path)

    if not path.exists():
        return []

    try:
        lines = path.read_text(errors="ignore").splitlines()
    except Exception:
        return []

    start = max(1, line_number - radius)
    end = min(len(lines), line_number + radius)

    preview = []

    for i in range(start, end + 1):
        preview.append((i, lines[i - 1]))

    return preview
