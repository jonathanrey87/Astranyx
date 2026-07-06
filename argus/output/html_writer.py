from pathlib import Path
from html import escape


def write_html_report(report: dict, output_path: Path) -> None:
    """Write a simple HTML report."""

    target = escape(str(report.get("target", "Unknown")))

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Argus Report</title>
<style>
body {{
    font-family: Arial, sans-serif;
    margin: 40px;
    line-height: 1.6;
}}
pre {{
    background: #f4f4f4;
    padding: 15px;
    border-radius: 5px;
}}
</style>
</head>
<body>

<h1>Argus Investigation Report</h1>

<h2>Target</h2>
<p>{target}</p>

<h2>Analysis Data</h2>
<pre>{escape(str(report))}</pre>

</body>
</html>
"""

    output_path.write_text(html, encoding="utf-8")
