"""Standalone HTML dashboard for unverified AI investigations."""

from __future__ import annotations

from html import escape
from typing import Any


def render_dashboard(report: dict[str, Any]) -> str:
    """Render a self-contained, escaped investigation dashboard."""
    investigations = report.get("investigations", [])
    errors = report.get("errors", [])
    generated = escape(str(report.get("generated", "Unknown")))

    cards = []
    for item in investigations:
        fingerprint = escape(str(item.get("finding_fingerprint", "")))
        summary = escape(str(item.get("summary", "")))
        impact = escape(str(item.get("impact", "")))
        next_step = escape(str(item.get("next_step", "")))

        cards.append(f"""
            <article class="finding">
                <div class="finding-top">
                    <span class="tag">AI ANALYSIS · UNVERIFIED</span>
                    <span class="sr-only"> | </span>
                    <span class="status">AWAITING VALIDATION</span>
                </div>
                <h2>{fingerprint}</h2>
                <div class="details">
                    <section>
                        <h3>Investigation summary</h3>
                        <p>{summary}</p>
                    </section>
                    <section>
                        <h3>Potential impact</h3>
                        <p>{impact}</p>
                    </section>
                    <section class="validation">
                        <h3>Recommended validation</h3>
                        <p>{next_step}</p>
                    </section>
                </div>
            </article>
            """)

    content = "\n".join(cards) or (
        '<div class="empty">No AI investigations are available.</div>'
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy"
      content="default-src 'none'; style-src 'unsafe-inline'">
<title>Astranyx | Investigation Dashboard</title>
<style>
:root {{
    color-scheme: dark;
    font-family: Inter, system-ui, sans-serif;
}}
* {{ box-sizing: border-box; }}
body {{
    margin: 0;
    color: #e9f7ff;
    background:
        radial-gradient(ellipse at 85% 0%, #123e59 0%, transparent 45%),
        linear-gradient(135deg, #030b15, #071a2b 65%, #04111d);
    min-height: 100vh;
}}
header {{
    border-bottom: 1px solid #1a4662;
    background: #061525dd;
    padding: 22px max(24px, calc((100vw - 1160px)/2));
}}
.brand {{
    color: #50d9ff;
    font-weight: 900;
    letter-spacing: 5px;
    font-size: 24px;
}}
.subtitle {{
    color: #86a9c2;
    font-size: 11px;
    letter-spacing: 2px;
    margin-top: 6px;
}}
main {{
    max-width: 1160px;
    margin: 0 auto;
    padding: 40px 24px 80px;
}}
.eyebrow {{
    color: #56d9ff;
    text-transform: uppercase;
    font-size: 11px;
    font-weight: 700;
    letter-spacing: 2px;
}}
h1 {{ font-size: clamp(28px, 4vw, 44px); margin: 12px 0; }}
.intro {{ color: #a7bed0; max-width: 780px; line-height: 1.7; }}
.stats {{
    display: grid;
    grid-template-columns: repeat(3, minmax(0, 1fr));
    gap: 16px;
    margin: 32px 0;
}}
.stat, .finding {{
    background: #0c2538e8;
    border: 1px solid #22516b;
    border-radius: 16px;
}}
.stat {{ padding: 24px; }}
.stat-label {{
    color: #95b3c7;
    font-size: 12px;
    text-transform: uppercase;
    letter-spacing: 1px;
}}
.stat-value {{
    color: #55d9ff;
    font-size: 38px;
    font-weight: 800;
    margin-top: 12px;
}}
.warning {{ color: #ffc977; }}
.finding {{
    margin-top: 22px;
    padding: 28px;
    box-shadow: 0 12px 38px #00000024;
}}
.finding-top {{
    display: flex;
    flex-wrap: wrap;
    gap: 12px;
    justify-content: space-between;
    align-items: center;
}}
.sr-only {{
    position: absolute;
    width: 1px;
    height: 1px;
    padding: 0;
    margin: -1px;
    overflow: hidden;
    clip: rect(0, 0, 0, 0);
    white-space: nowrap;
    border: 0;
}}
.tag {{
    color: #ffca77;
    font-size: 11px;
    font-weight: 800;
    letter-spacing: 1px;
}}
.status {{
    border: 1px solid #75552a;
    background: #3c2b1b;
    color: #ffcb7a;
    border-radius: 100px;
    padding: 7px 12px;
    font-size: 10px;
    font-weight: 800;
}}
h2 {{
    margin: 22px 0;
    font-size: 21px;
    overflow-wrap: anywhere;
}}
.details {{
    display: grid;
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: 18px;
}}
.details section {{
    padding: 18px;
    background: #071a2b;
    border: 1px solid #183e57;
    border-radius: 12px;
    min-width: 0;
}}
.details .validation {{
    grid-column: 1 / -1;
    border-left: 3px solid #3bd3ff;
}}
h3 {{ color: #62d7ff; font-size: 13px; margin: 0 0 12px; }}
p {{
    line-height: 1.7;
    overflow-wrap: anywhere;
    white-space: pre-wrap;
}}
.details p {{ margin: 0; color: #d4e6f1; }}
.empty {{
    border: 1px dashed #35637d;
    padding: 36px;
    border-radius: 14px;
    color: #a7bed0;
}}
footer {{
    border-top: 1px solid #21465f;
    margin-top: 42px;
    padding-top: 24px;
    color: #88a7bc;
    font-size: 12px;
    line-height: 1.8;
}}
@media (max-width: 640px) {{
    .stats {{ grid-template-columns: 1fr; }}
    .details {{ grid-template-columns: 1fr; }}
    .details .validation {{ grid-column: auto; }}
    .finding {{ padding: 18px; }}
}}
</style>
</head>
<body>
<header>
    <div class="brand">ASTRANYX</div>
    <div class="subtitle">DIGITAL EVIDENCE DECODED</div>
</header>
<main>
    <div class="eyebrow">Investigation intelligence / AI analysis</div>
    <h1>Investigation Overview</h1>
    <p class="intro">
        AI-generated explanations are unverified and require
        independent validation. This dashboard does not establish
        that a vulnerability exists.
    </p>

    <div class="stats">
        <div class="stat">
            <div class="stat-label">AI investigations</div>
            <div class="stat-value">{len(investigations)}</div>
        </div>
        <div class="stat">
            <div class="stat-label">Independently validated</div>
            <div class="stat-value">0</div>
        </div>
        <div class="stat">
            <div class="stat-label">Analysis errors</div>
            <div class="stat-value warning">{len(errors)}</div>
        </div>
    </div>

    <div class="eyebrow">Investigation findings</div>
    {content}

    <footer>
        Generated: {generated}<br>
        AI ANALYSIS · UNVERIFIED<br>
        Generated by Astranyx. AI analysis is not proof of exploitation.
    </footer>
</main>
</body>
</html>
"""
