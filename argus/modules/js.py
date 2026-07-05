from pathlib import Path
import re
import json

PATTERNS = {
    "network_fetch": r"fetch\(",
    "axios": r"axios",
    "graphql": r"graphql|mutation|operationName|query",
    "oauth": r"oauth|saml|scim|sso",
    "auth": r"token|csrf|session|cookie|webauthn|passkey",
    "uploads": r"upload|attachment|file|files|import|export",
    "collaboration": r"invite|team|organization|workspace|member|permission|comment",
    "admin": r"admin|internal|staff|employee",
}

ROUTE_PATTERN = re.compile(
    r"""["'`]((?:https?://|/)[A-Za-z0-9._~:/?#@!$&()*+,;=%\-\[\]]+)["'`]"""
)


def analyze(path, output=None):
    """
    Analyze JavaScript bundles for interesting security-related patterns.

    Args:
        path (str): Directory containing .js files
        output (str|None): Optional JSON output file
    """

    base = Path(path)

    if not base.exists():
        raise SystemExit(f"[!] Path not found: {base}")

    js_files = list(base.glob("*.js"))

    if not js_files:
        raise SystemExit(f"[!] No JavaScript files found in {base}")

    results = {}
    routes = set()

    for file in js_files:
        try:
            text = file.read_text(errors="ignore")
        except Exception as e:
            print(f"[!] Failed reading {file}: {e}")
            continue

        findings = {}

        for name, pattern in PATTERNS.items():
            matches = re.findall(pattern, text, flags=re.IGNORECASE)

            if matches:
                findings[name] = len(matches)

        for match in ROUTE_PATTERN.findall(text):
            routes.add(match)

        if findings:
            results[file.name] = findings

    report = {
        "target": base.name,
        "files_analyzed": len(js_files),
        "summary": results,
        "routes": sorted(routes),
    }

    result = json.dumps(report, indent=2)

    if output:
        output_path = Path(output)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        with output_path.open("w") as f:
            f.write(result)

        print(f"[+] Report written to {output_path}")

    print(result)
