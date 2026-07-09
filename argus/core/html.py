from pathlib import Path
import html
import csv
import json


def confidence_band(conf):
    if conf >= 80:
        return "high"
    if conf >= 40:
        return "medium"
    return "low"


def risk_score(findings):
    if not findings:
        return 0

    points = 0
    for f in findings:
        if f.confidence >= 90:
            points += 10
        elif f.confidence >= 70:
            points += 7
        elif f.confidence >= 40:
            points += 4
        else:
            points += 1

    max_points = len(findings) * 10
    return round((points / max_points) * 100)


def recommendation(f):
    recs = {
        "Public REST Permission": "Inspect the route callback and verify capability checks or authentication are enforced.",
        "Potential Taint Flow": "Trace the variable from source to sink and confirm whether user input reaches a dangerous operation.",
        "React Dangerous Sink": "Verify HTML is escaped or sanitized before rendering.",
        "DOM Sink": "Check whether user-controlled data reaches innerHTML.",
        "SSRF Sink": "Verify URL validation, allowlists, and blocked internal network destinations.",
        "SQL Query": "Review whether prepare(), whitelisting, or strict validation is used.",
        "Upload Handler": "Verify nonce, capability checks, MIME validation, extension checks, and upload destination.",
        "Deserialization": "Confirm serialized data cannot be attacker-controlled and use allowed_classes=false for unserialize().",
        "Dynamic Include": "Trace include path origin and ensure it cannot be user-controlled.",
    }
    return recs.get(f.category, "Review this code path manually.")


def render(report, output_dir):
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    findings = sorted(report.findings, key=lambda f: (-f.confidence, f.file, f.line))
    summary = report.summary()
    score = risk_score(findings)

    high = sum(1 for f in findings if f.confidence >= 80)
    medium = sum(1 for f in findings if 40 <= f.confidence < 80)
    low = sum(1 for f in findings if f.confidence < 40)

    rows = ""
    for i, f in enumerate(findings):
        band = confidence_band(f.confidence)
        rows += f"""
        <tr class="finding-row {band}" data-band="{band}" data-category="{html.escape(f.category)}">
            <td><button class="toggle" onclick="toggleDetails({i})">▶</button></td>
            <td>{html.escape(f.severity)}</td>
            <td><span class="badge {band}">{f.confidence}%</span></td>
            <td>{html.escape(f.category)}</td>
            <td class="file">{html.escape(f.file)}</td>
            <td>{f.line}</td>
            <td>{html.escape(f.reason)}</td>
        </tr>
        <tr id="details-{i}" class="details">
            <td colspan="7">
                <div class="details-box">
                    <h4>Evidence</h4>
                    <pre>{html.escape(f.evidence)}</pre>
                    <h4>Recommendation</h4>
                    <p>{html.escape(recommendation(f))}</p>
                    <h4>Note</h4>
                    <p>{html.escape(f.note)}</p>
                </div>
            </td>
        </tr>
        """

    category_labels = list(summary["categories"].keys())
    category_values = list(summary["categories"].values())

    page = f"""
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>Argus Security Report</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<style>
:root {{
    --bg: #0f172a;
    --panel: #111827;
    --card: #1f2937;
    --text: #e5e7eb;
    --muted: #9ca3af;
    --high: #ef4444;
    --medium: #f59e0b;
    --low: #22c55e;
    --line: #374151;
}}

body {{
    margin: 0;
    font-family: Arial, Helvetica, sans-serif;
    background: var(--bg);
    color: var(--text);
}}

.header {{
    padding: 36px 48px;
    background: linear-gradient(135deg, #111827, #1e3a8a);
    border-bottom: 1px solid var(--line);
}}

.header h1 {{
    margin: 0;
    font-size: 38px;
    letter-spacing: 1px;
}}

.header p {{
    margin: 8px 0 0;
    color: var(--muted);
}}

.container {{
    padding: 28px 48px;
}}

.cards {{
    display: grid;
    grid-template-columns: repeat(5, minmax(140px, 1fr));
    gap: 16px;
    margin-bottom: 28px;
}}

.card {{
    background: var(--card);
    border: 1px solid var(--line);
    border-radius: 12px;
    padding: 18px;
}}

.card .label {{
    color: var(--muted);
    font-size: 13px;
}}

.card .value {{
    font-size: 30px;
    font-weight: bold;
    margin-top: 8px;
}}

.score {{
    color: #93c5fd;
}}

.high-text {{ color: var(--high); }}
.medium-text {{ color: var(--medium); }}
.low-text {{ color: var(--low); }}

.grid {{
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 18px;
    margin-bottom: 28px;
}}

.panel {{
    background: var(--panel);
    border: 1px solid var(--line);
    border-radius: 12px;
    padding: 18px;
}}

.toolbar {{
    display: flex;
    gap: 12px;
    flex-wrap: wrap;
    margin-bottom: 16px;
    align-items: center;
}}

input[type="text"] {{
    background: #020617;
    border: 1px solid var(--line);
    color: var(--text);
    padding: 10px;
    border-radius: 8px;
    min-width: 280px;
}}

label {{
    color: var(--muted);
}}

table {{
    width: 100%;
    border-collapse: collapse;
    background: var(--panel);
    border: 1px solid var(--line);
    border-radius: 12px;
    overflow: hidden;
}}

th, td {{
    border-bottom: 1px solid var(--line);
    padding: 12px;
    text-align: left;
    vertical-align: top;
}}

th {{
    background: #020617;
    color: #cbd5e1;
    position: sticky;
    top: 0;
}}

.badge {{
    padding: 4px 8px;
    border-radius: 999px;
    font-weight: bold;
}}

.badge.high {{
    color: white;
    background: var(--high);
}}

.badge.medium {{
    color: #111827;
    background: var(--medium);
}}

.badge.low {{
    color: #052e16;
    background: var(--low);
}}

.toggle {{
    background: transparent;
    border: 0;
    color: var(--text);
    cursor: pointer;
    font-size: 16px;
}}

.details {{
    display: none;
}}

.details-box {{
    background: #020617;
    border: 1px solid var(--line);
    border-radius: 8px;
    padding: 14px;
}}

pre {{
    white-space: pre-wrap;
    background: #0b1220;
    border: 1px solid var(--line);
    padding: 12px;
    border-radius: 8px;
    color: #d1d5db;
}}

.file {{
    color: #93c5fd;
    font-family: monospace;
}}

.footer {{
    color: var(--muted);
    margin-top: 24px;
    font-size: 13px;
}}
</style>
</head>
<body>

<div class="header">
    <h1>ARGUS SECURITY REPORT</h1>
    <p>WordPress Static Analysis Dashboard</p>
    <p><strong>Target:</strong> {html.escape(summary["target"])}</p>
    <p><strong>Generated:</strong> {html.escape(summary["generated"])}</p>
</div>

<div class="container">

<div class="cards">
    <div class="card">
        <div class="label">Risk Score</div>
        <div class="value score">{score}/100</div>
    </div>
    <div class="card">
        <div class="label">Total Findings</div>
        <div class="value">{summary["total"]}</div>
    </div>
    <div class="card">
        <div class="label">High Confidence</div>
        <div class="value high-text">{high}</div>
    </div>
    <div class="card">
        <div class="label">Medium Confidence</div>
        <div class="value medium-text">{medium}</div>
    </div>
    <div class="card">
        <div class="label">Low Confidence</div>
        <div class="value low-text">{low}</div>
    </div>
</div>

<div class="grid">
    <div class="panel">
        <h2>Confidence Breakdown</h2>
        <canvas id="confidenceChart"></canvas>
    </div>
    <div class="panel">
        <h2>Findings by Category</h2>
        <canvas id="categoryChart"></canvas>
    </div>
</div>

<div class="panel">
    <h2>Findings</h2>

    <div class="toolbar">
        <input type="text" id="searchBox" placeholder="Search findings..." onkeyup="filterRows()">
        <label><input type="checkbox" class="bandFilter" value="high" checked onchange="filterRows()"> High</label>
        <label><input type="checkbox" class="bandFilter" value="medium" checked onchange="filterRows()"> Medium</label>
        <label><input type="checkbox" class="bandFilter" value="low" checked onchange="filterRows()"> Low</label>
    </div>

    <table id="findingsTable">
        <thead>
            <tr>
                <th></th>
                <th>Severity</th>
                <th>Confidence</th>
                <th>Category</th>
                <th>File</th>
                <th>Line</th>
                <th>Reason</th>
            </tr>
        </thead>
        <tbody>
            {rows}
        </tbody>
    </table>
</div>

<div class="footer">
    Generated by Argus Threat Intelligence Automation Framework.
</div>

</div>

<script>
function toggleDetails(id) {{
    const row = document.getElementById("details-" + id);
    row.style.display = row.style.display === "table-row" ? "none" : "table-row";
}}

function filterRows() {{
    const q = document.getElementById("searchBox").value.toLowerCase();
    const checked = Array.from(document.querySelectorAll(".bandFilter:checked")).map(x => x.value);

    document.querySelectorAll(".finding-row").forEach(row => {{
        const band = row.dataset.band;
        const text = row.innerText.toLowerCase();
        const visible = checked.includes(band) && text.includes(q);
        row.style.display = visible ? "table-row" : "none";

        const id = row.nextElementSibling;
        if (!visible && id && id.classList.contains("details")) {{
            id.style.display = "none";
        }}
    }});
}}

new Chart(document.getElementById("confidenceChart"), {{
    type: "doughnut",
    data: {{
        labels: ["High", "Medium", "Low"],
        datasets: [{{
            data: [{high}, {medium}, {low}]
        }}]
    }}
}});

new Chart(document.getElementById("categoryChart"), {{
    type: "bar",
    data: {{
        labels: {json.dumps(category_labels)},
        datasets: [{{
            label: "Findings",
            data: {json.dumps(category_values)}
        }}]
    }},
    options: {{
        indexAxis: "y"
    }}
}});
</script>

</body>
</html>
"""

    (output_dir / "index.html").write_text(page)
    (output_dir / "findings.json").write_text(report.to_json())

    with (output_dir / "findings.csv").open("w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["severity", "confidence", "category", "file", "line", "reason", "evidence"])
        for item in findings:
            writer.writerow([
                item.severity,
                item.confidence,
                item.category,
                item.file,
                item.line,
                item.reason,
                item.evidence,
            ])
