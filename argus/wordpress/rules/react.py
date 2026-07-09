import re

RULES = [
    {
        "category": "React Dangerous Sink",
        "severity": "Medium",
        "pattern": re.compile(r"dangerouslySetInnerHTML"),
    },
    {
        "category": "DOM Sink",
        "severity": "Medium",
        "pattern": re.compile(r"\.innerHTML\s*="),
    },
    {
        "category": "HTML Escaping",
        "severity": "Info",
        "pattern": re.compile(r"DOMPurify|escapeHtml|htmlspecialchars|&lt;|&amp;|replace\(/</g"),
    },
]
