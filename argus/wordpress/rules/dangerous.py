import re

RULES = [
    {
        "category": "Dangerous Function",
        "severity": "High",
        "pattern": re.compile(
            r"\beval\s*\(|\bsystem\s*\(|\bshell_exec\s*\(|\bexec\s*\(|\bpassthru\s*\("
        ),
    },
]
