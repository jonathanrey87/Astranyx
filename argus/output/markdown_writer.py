from pathlib import Path


def write_markdown_summary(report: dict, output_path: Path) -> None:
    """Write a Markdown summary."""

    target = report.get("target", "Unknown")

    md = (
        "# Argus Investigation Summary\n\n"
        f"## Target\n\n{target}\n\n"
        "## Analysis\n\n"
        "```\n"
        f"{report}\n"
        "```\n"
    )

    output_path.write_text(md, encoding="utf-8")
