import re

RULES = [
    {
        "category": "Deserialization",
        "severity": "Medium",
        "pattern": re.compile(r"\bunserialize\b|\bmaybe_unserialize\b"),
    },
]
