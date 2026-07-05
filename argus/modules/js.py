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

ROUTE_PATTERN = re.compile(r"""["'`]((?:https?://|/)[A-Za-z0-9._~:/?#@!$&()*+,;=%\-\[\]]+)["'`]""")


def analyze(path):
    base = Path(path)

    if not base.exists():
        raise SystemExit(f"Path not found: {base}")

    results = {}
    routes = set()

    for file in base.glob("*.js"):
        text = file.read_text(errors="ignore")

        findings = {}
        for name, pattern in PATTERNS.items():
            matches = re.findall(pattern, text, flags=re.I)
            if matches:
                findings[name] = len(matches)

        for match in ROUTE_PATTERN.findall(text):
            routes.add(match)

        if findings:
            results[file.name] = findings

    output = {
        "files_analyzed": len(list(base.glob("*.js"))),
        "summary": results,
        "routes": sorted(routes)[:300],
    }

    print(json.dumps(output, indent=2))
