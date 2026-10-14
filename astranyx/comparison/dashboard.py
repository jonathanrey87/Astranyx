"""Self-contained analyst view of a baseline comparison."""

from __future__ import annotations

import html
from typing import Any

OUTCOMES = {
    "regressed": (
        "Regressed",
        "Review the increased severity or confidence and prioritize remediation.",
    ),
    "new": ("New", "Review the evidence, confirm impact, and assign remediation."),
    "changed": (
        "Changed",
        "Compare the evidence and reassess the existing remediation plan.",
    ),
    "persistent": (
        "Recurring",
        "Check remediation progress; the finding remains in this report.",
    ),
    "fixed": (
        "Not observed",
        "Confirm equivalent scan coverage and verify the fix before closing.",
    ),
}


def _escape(value: Any) -> str:
    return html.escape(str(value if value is not None else "Not supplied"), quote=True)


def render(result: dict[str, Any]) -> str:
    """Render comparison data without external resources or executable finding data."""
    cards, rows, options = [], [], []
    for outcome, (label, guidance) in OUTCOMES.items():
        cards.append(
            f'<div class="card"><strong>{len(result[outcome])}</strong>{label}</div>'
        )
        options.append(f'<option value="{outcome}">{label}</option>')
        for entry in result[outcome]:
            finding = entry.get("after", entry)
            search = " ".join(
                str(finding.get(key, ""))
                for key in ("category", "file", "fingerprint", "evidence", "reason")
            )
            changes = "".join(
                f'<tr><th scope="row">{_escape(field)}</th>'
                f"<td><pre>{_escape(values['before'])}</pre></td>"
                f"<td><pre>{_escape(values['after'])}</pre></td></tr>"
                for field, values in entry.get("changes", {}).items()
            )
            comparison = (
                "<h3>What changed</h3><table><thead><tr><th>Field</th>"
                "<th>Before</th><th>After</th></tr></thead>"
                f"<tbody>{changes}</tbody></table>"
                if changes
                else ""
            )
            rows.append(
                f'<article class="finding" data-outcome="{outcome}" '
                f'data-search="{_escape(search.lower())}">'
                f'<div class="badges">{label} · {_escape(finding.get("severity"))}</div>'
                f"<h3>{_escape(finding.get('category', 'Finding'))}</h3>"
                f'<p class="location">{_escape(finding.get("file"))}:'
                f"{_escape(finding.get('line'))}</p>"
                f"<p><strong>Next step:</strong> {guidance}</p>"
                "<details><summary>Evidence and assessment</summary>"
                f"<p>Fingerprint: <code>{_escape(finding.get('fingerprint'))}</code></p>"
                f"<p>Confidence: {_escape(finding.get('confidence'))}</p>"
                f"<h3>Evidence</h3><pre>{_escape(finding.get('evidence'))}</pre>"
                f"<h3>Assessment rationale</h3><pre>{_escape(finding.get('reason'))}</pre>"
                f"{comparison}</details></article>"
            )
    return (
        """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Astranyx Remediation Review</title>
<style>
:root{color-scheme:dark;font:16px/1.6 system-ui,sans-serif;background:#091321;color:#e7edf6}
*{box-sizing:border-box}body{margin:0}main{max-width:1100px;margin:auto;padding:32px 20px}
h1{font-size:clamp(28px,5vw,44px);margin:4px 0}h3{margin:8px 0}
.eyebrow,.badges{color:#65dfcf}.muted,.location{color:#aabbd0;overflow-wrap:anywhere}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px;margin:24px 0}
.card,.finding{background:#122136;border:1px solid #30435c;border-radius:12px;padding:18px}
.card strong{display:block;font-size:32px}.finding{margin:14px 0}
.toolbar{display:flex;flex-wrap:wrap;gap:12px}input,select{font:inherit;padding:10px;border:1px solid #60748f;border-radius:6px;background:#122136;color:inherit}
input{flex:1;min-width:180px}summary{cursor:pointer;color:#65dfcf}pre,code{overflow-wrap:anywhere;white-space:pre-wrap}
pre{background:#091321;padding:12px;border-radius:6px}table{width:100%;table-layout:fixed;border-collapse:collapse}th,td{text-align:left;vertical-align:top;padding:8px;border-bottom:1px solid #30435c}
[hidden]{display:none!important}:focus-visible{outline:3px solid #65dfcf;outline-offset:3px}
@media print{:root{color-scheme:light;background:white;color:black}.toolbar{display:none}.card,.finding{background:white;border-color:#aaa}pre{background:#eee}.muted,.location,.badges{color:#333}}
</style></head><body><main>
<div class="eyebrow">ASTRANYX · REMEDIATION REVIEW</div>
<h1>What changed since the baseline</h1>
<p class="muted">Review regressions and new findings first, then check ongoing remediation.</p>
"""
        + (
            f'<p class="muted">Baseline: {_escape(result["baseline"])}<br>'
            f"Current: {_escape(result['current'])}</p>"
            '<section class="grid" aria-label="Comparison summary">'
            + "".join(cards)
            + "</section>"
            "<p>“Not observed” means absent from this report, not a verified fix. "
            "Coverage changes can affect results. Changed findings may be paired by rule and file "
            "when a unique match exists; increased confidence alone can mark a regression.</p>"
            '<div class="toolbar"><input id="search" type="search" aria-label="Search findings" '
            'placeholder="Search findings, files, or evidence"><select id="outcome" '
            'aria-label="Filter by outcome"><option value="all">All outcomes</option>'
            + "".join(options)
            + "</select></div>"
            f'<p id="count" role="status">{len(rows)} findings shown</p>'
            + "".join(rows)
            + f'<p id="empty"{" hidden" if rows else ""}>No findings match this view.</p>'
        )
        + """
<footer class="muted">Offline comparison report · Review guidance is not a verification decision.</footer>
</main><script>
const search=document.getElementById('search'),outcome=document.getElementById('outcome');
function filter(){let shown=0;const query=search.value.toLowerCase();
document.querySelectorAll('.finding').forEach(row=>{
row.hidden=!(row.dataset.search.includes(query)&&(outcome.value==='all'||row.dataset.outcome===outcome.value));
if(!row.hidden)shown++;
});document.getElementById('count').textContent=shown+' findings shown';
document.getElementById('empty').hidden=shown!==0;}
search.addEventListener('input',filter);outcome.addEventListener('change',filter);
</script></body></html>
"""
    )
