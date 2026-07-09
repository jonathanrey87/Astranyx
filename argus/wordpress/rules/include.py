import re

RULES = [
    {
        "category": "Dynamic Include",
        "severity": "Medium",
        "pattern": re.compile(r"\b(include|include_once|require|require_once)\b"),
    },
]
