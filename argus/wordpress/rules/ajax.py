import re

RULES = [
    {
        "category": "AJAX Route",
        "severity": "Info",
        "pattern": re.compile(r"wp_ajax_[a-zA-Z0-9_]+"),
    },
    {
        "category": "Public AJAX Route",
        "severity": "High",
        "pattern": re.compile(r"wp_ajax_nopriv_[a-zA-Z0-9_]+"),
    },
]
