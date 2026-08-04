import json
from pathlib import Path

from argus.output.html_writer import write_html_report
from argus.output.markdown_writer import write_markdown_summary


def run(report_json: str) -> None:
    path = Path(report_json)

    if not path.exists():
        raise SystemExit(f"[!] Report JSON not found: {path}")

    with path.open("r", encoding="utf-8") as f:
        report = json.load(f)

    output_dir = path.parent
    html_path = output_dir / "report.html"
    md_path = output_dir / "summary.md"

    write_html_report(report, html_path)
    write_markdown_summary(report, md_path)

    print(f"[+] HTML report written to {html_path}")
    print(f"[+] Markdown summary written to {md_path}")
