from pathlib import Path
from html import escape
from datetime import datetime


def _total_by_category(summary: dict) -> dict:
    totals = {}
    for findings in summary.values():
        for category, count in findings.items():
            totals[category] = totals.get(category, 0) + count
    return dict(sorted(totals.items(), key=lambda item: item[1], reverse=True))


def _interesting_routes(routes: list[str]) -> list[str]:
    keywords = (
        "/api",
        "/graphql",
        "/login",
        "/logout",
        "/signup",
        "/oauth",
        "/session",
        "/auth",
        "/user",
        "/admin",
        "/file",
        "/files",
        "/upload",
        "/embed",
    )

    ignored = (
        "/dev/",
        "/proc",
        "/tmp",
        "/_next/static",
        "/_netlify/_next/static",
        "http://example",
        "https://example",
        "https://a",
        "http://n",
    )

    clean = []
    for route in routes:
        if any(route.startswith(i) for i in ignored):
            continue
        if any(k in route.lower() for k in keywords):
            clean.append(route)

    return sorted(set(clean))[:50]


def _external_services(routes: list[str]) -> list[str]:
    services = []

    checks = {
        "Google OAuth": "accounts.google.com",
        "Sentry": "sentry.io",
        "Sanity": "sanity.io",
        "Statsig": "statsig",
        "Greenhouse": "greenhouse.io",
        "Vimeo": "vimeo.com",
        "Cloudflare DNS": "cloudflare-dns.com",
    }

    for name, marker in checks.items():
        if any(marker in route for route in routes):
            services.append(name)

    return services


def _bar(value: int, max_value: int) -> str:
    if max_value <= 0:
        return ""
    blocks = max(1, round((value / max_value) * 20))
    return "█" * blocks


def write_html_report(report: dict, output_path: Path) -> None:
    """Write a structured HTML investigation report."""

    target = escape(str(report.get("target", "Unknown")))
    files_analyzed = report.get("files_analyzed", 0)
    summary = report.get("summary", {})
    routes = report.get("routes", [])

    category_totals = _total_by_category(summary)
    max_score = max(category_totals.values()) if category_totals else 1
    interesting_routes = _interesting_routes(routes)
    external_services = _external_services(routes)

    generated = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

    category_rows = "\n".join(
        f"""
        <tr>
            <td>{escape(category)}</td>
            <td>{count}</td>
            <td><span class="bar">{_bar(count, max_score)}</span></td>
        </tr>
        """
        for category, count in category_totals.items()
    )

    endpoint_items = "\n".join(
        f"<li><code>{escape(route)}</code></li>"
        for route in interesting_routes
    ) or "<li>No high-value routes identified.</li>"

    service_items = "\n".join(
        f"<li>{escape(service)}</li>"
        for service in external_services
    ) or "<li>No common third-party services identified.</li>"

    top_files = sorted(
        summary.items(),
        key=lambda item: sum(item[1].values()),
        reverse=True,
    )[:10]

    file_rows = "\n".join(
        f"""
        <tr>
            <td>{escape(filename)}</td>
            <td>{sum(findings.values())}</td>
            <td>{escape(", ".join(findings.keys()))}</td>
        </tr>
        """
        for filename, findings in top_files
    )

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Argus Investigation Report</title>
<style>
body {{
    font-family: Arial, sans-serif;
    background: #f6f7f9;
    color: #1f2937;
    margin: 0;
    padding: 0;
}}
.container {{
    max-width: 1100px;
    margin: 40px auto;
    background: white;
    padding: 40px;
    border-radius: 14px;
    box-shadow: 0 8px 30px rgba(0,0,0,0.08);
}}
h1 {{
    margin-bottom: 0;
}}
.subtitle {{
    color: #6b7280;
    margin-top: 6px;
}}
.section {{
    margin-top: 36px;
}}
.cards {{
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: 16px;
}}
.card {{
    background: #f3f4f6;
    padding: 20px;
    border-radius: 10px;
}}
.card strong {{
    font-size: 28px;
    display: block;
}}
table {{
    width: 100%;
    border-collapse: collapse;
}}
th, td {{
    padding: 12px;
    border-bottom: 1px solid #e5e7eb;
    text-align: left;
}}
th {{
    background: #f9fafb;
}}
code {{
    background: #eef2ff;
    padding: 3px 6px;
    border-radius: 5px;
}}
.bar {{
    color: #111827;
    letter-spacing: 1px;
}}
.checklist li {{
    margin: 8px 0;
}}
.footer {{
    margin-top: 40px;
    color: #6b7280;
    font-size: 14px;
}}
</style>
</head>
<body>
<div class="container">

<h1>Argus Investigation Report</h1>
<p class="subtitle">Evidence-driven JavaScript reconnaissance report</p>

<div class="section">
<h2>Executive Summary</h2>
<p>
Argus analyzed <strong>{files_analyzed}</strong> JavaScript bundles and identified
references related to authentication, GraphQL, uploads, collaboration, and administrative functionality.
This report does not confirm vulnerabilities. It highlights areas that deserve manual security review.
</p>
</div>

<div class="section cards">
<div class="card">
<strong>{files_analyzed}</strong>
Files analyzed
</div>
<div class="card">
<strong>{len(routes)}</strong>
Routes discovered
</div>
<div class="card">
<strong>{len(interesting_routes)}</strong>
High-value routes
</div>
</div>

<div class="section">
<h2>Target</h2>
<p>{target}</p>
<p><strong>Generated:</strong> {generated}</p>
</div>

<div class="section">
<h2>Attack Surface Summary</h2>
<table>
<thead>
<tr>
<th>Category</th>
<th>Matches</th>
<th>Signal</th>
</tr>
</thead>
<tbody>
{category_rows}
</tbody>
</table>
</div>

<div class="section">
<h2>High-Value Routes</h2>
<ul>
{endpoint_items}
</ul>
</div>

<div class="section">
<h2>External Services</h2>
<ul>
{service_items}
</ul>
</div>

<div class="section">
<h2>Top JavaScript Bundles by Signal Count</h2>
<table>
<thead>
<tr>
<th>Bundle</th>
<th>Total Matches</th>
<th>Categories</th>
</tr>
</thead>
<tbody>
{file_rows}
</tbody>
</table>
</div>

<div class="section">
<h2>Recommended Manual Review</h2>
<ul class="checklist">
<li>☐ Authentication and session handling</li>
<li>☐ OAuth and Google sign-in flows</li>
<li>☐ Authorization checks around user and file routes</li>
<li>☐ Upload and import/export functionality</li>
<li>☐ GraphQL operations and mutations</li>
<li>☐ Admin or internal functionality references</li>
</ul>
</div>

<p class="footer">
Generated by Argus Report Engine.
</p>

</div>
</body>
</html>
"""

    output_path.write_text(html, encoding="utf-8")
