import re

RULES = [
    {
        "category": "SQL Query",
        "severity": "Info",
        "pattern": re.compile(r"\$wpdb->(query|get_results|get_row|get_var)"),
    },
    {
        "category": "Possible Unsafe SQL",
        "severity": "High",
        "pattern": re.compile(r"\$wpdb->(query|get_results|get_row|get_var).*?\$_(GET|POST|REQUEST)"),
    },
]
