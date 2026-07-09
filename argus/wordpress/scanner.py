from pathlib import Path
from dataclasses import dataclass

from argus.wordpress.analyzer import analyze_finding
from argus.wordpress.taint import analyze as taint_analyze
from argus.wordpress.rules.registry import get_rules_for_file
from argus.core.report import Report
from argus.core.html import render
from argus.core.sarif import export as export_sarif


@dataclass
class Finding:
    category: str
    severity: str
    file: str
    full_path: str
    line: int
    evidence: str
    note: str
    confidence: int = 50
    reason: str = ""


def make_note(category):
    notes = {
        "Public AJAX Route": "Unauthenticated AJAX endpoint. Review callback for authentication, nonce validation, and capability checks.",
        "Public REST Permission": "Public REST endpoint. Verify authorization inside the callback.",
        "Possible Unsafe SQL": "User-controlled input may reach SQL.",
        "SSRF Sink": "Review whether attacker-controlled URLs can reach outbound requests.",
        "Upload Handler": "Review upload validation, MIME checks, and destination path.",
        "Deserialization": "Review whether serialized input can be attacker-controlled.",
        "Dangerous Function": "Determine whether attacker-controlled input reaches this execution sink.",
        "Dynamic Include": "Determine whether the included path is user-controlled.",
        "React Dangerous Sink": "Verify that HTML is escaped or sanitized before rendering.",
        "DOM Sink": "Review whether user-controlled HTML reaches innerHTML.",
        "HTML Escaping": "Escaping detected.",
    }
    return notes.get(category, "Manual review recommended.")


def is_comment(line):
    stripped = line.strip()
    return (
        stripped.startswith("//")
        or stripped.startswith("#")
        or stripped.startswith("*")
        or stripped.startswith("/*")
    )


def scan_file(path: Path, root: Path):
    findings = []

    try:
        lines = path.read_text(errors="ignore").splitlines()
    except Exception:
        return findings

    rules = get_rules_for_file(path)

    for idx, line in enumerate(lines, start=1):
        if is_comment(line):
            continue

        for rule in rules:
            if rule["pattern"].search(line):
                finding = Finding(
                    category=rule["category"],
                    severity=rule["severity"],
                    file=str(path.relative_to(root)),
                    full_path=str(path),
                    line=idx,
                    evidence=line.strip()[:250],
                    note=make_note(rule["category"]),
                )

                finding = analyze_finding(finding, lines)
                findings.append(finding)

    if path.suffix == ".php":
        for tf in taint_analyze(lines):
            findings.append(
                Finding(
                    category="Potential Taint Flow",
                    severity="High",
                    file=str(path.relative_to(root)),
                    full_path=str(path),
                    line=1,
                    evidence=f"{tf.variable} -> {tf.sink}",
                    note=tf.reason,
                    confidence=tf.confidence,
                    reason=tf.reason,
                )
            )

    return findings


def summarize(findings):
    summary = {}
    for f in findings:
        summary[f.category] = summary.get(f.category, 0) + 1
    return summary


def scan_plugin(plugin_path):
    root = Path(plugin_path).expanduser().resolve()

    if not root.exists():
        raise FileNotFoundError(root)

    findings = []

    for ext in ("*.php", "*.js", "*.jsx", "*.ts", "*.tsx"):
        for file in root.rglob(ext):
            if any(x in file.parts for x in ("vendor", "node_modules", ".git")):
                continue

            findings.extend(scan_file(file, root))

    return findings


def run(plugin_path):
    findings = scan_plugin(plugin_path)
    summary = summarize(findings)

    print()
    print("=" * 60)
    print("Argus WordPress Security Audit")
    print("=" * 60)
    print()

    print("Summary")
    print("-------")
    for k, v in sorted(summary.items()):
        print(f"{k:28} {v}")

    print()
    print("Findings")
    print("--------")

    findings.sort(key=lambda f: (-f.confidence, f.file, f.line))

    for f in findings:
        print(f"[{f.severity}] {f.category}")
        print(f"Confidence : {f.confidence}%")
        print(f"Reason     : {f.reason}")
        print(f"Location   : {f.file}:{f.line}")
        print(f"Evidence   : {f.evidence}")
        print()

    print(f"Total Findings: {len(findings)}")

    report = Report(plugin_path, findings)
    out = Path("reports") / Path(plugin_path).name
    render(report, out)
    export_sarif(report, out)

    print()
    print("=" * 60)
    print("Argus Report Generated")
    print("=" * 60)
    print(f"HTML : {out / 'index.html'}")
    print(f"JSON : {out / 'findings.json'}")
    print(f"CSV  : {out / 'findings.csv'}")
    print(f"SARIF: {out / 'findings.sarif'}")


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 2:
        print("Usage:")
        print("python -m argus.wordpress.scanner <plugin_directory>")
        raise SystemExit(1)

    run(sys.argv[1])
