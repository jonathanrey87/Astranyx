from pathlib import Path
import html


def markdown_template(workspace):
    return f"""# {workspace.name}

## Executive Summary

## Target

## Security Boundary

## Attack Surface

## Steps to Reproduce

1.

2.

3.

## Expected Behavior

## Observed Behavior

## Impact

## Evidence

### Requests

### Responses

### Screenshots

### Video

## Timeline

## Notes

## Suggested Remediation
"""


def html_template(title, markdown_content):
    escaped = html.escape(markdown_content)
    body = escaped.replace("\n", "<br>\n")

    return f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>{html.escape(title)}</title>
<style>
body {{
    font-family: Arial, sans-serif;
    margin: 40px;
    background: #f8fafc;
    color: #111827;
}}
.report {{
    max-width: 900px;
    margin: auto;
    background: white;
    padding: 32px;
    border-radius: 12px;
    border: 1px solid #e5e7eb;
}}
h1 {{
    color: #111827;
}}
.content {{
    line-height: 1.6;
}}
</style>
</head>
<body>
<div class="report">
<h1>{html.escape(title)}</h1>
<div class="content">
{body}
</div>
</div>
</body>
</html>
"""


def run(args):
    workspace = Path(args.path)

    if not workspace.exists():
        print(f"[-] Workspace not found: {workspace}")
        return 1

    reports = Path("reports")
    reports.mkdir(exist_ok=True)

    content = markdown_template(workspace)

    md_report = reports / f"{workspace.name}.md"
    md_report.write_text(content)

    print("[+] Report template created:")
    print(md_report)

    if getattr(args, "html", False):
        html_report = reports / f"{workspace.name}.html"
        html_report.write_text(html_template(workspace.name, content))
        print("[+] HTML report created:")
        print(html_report)

    return 0
