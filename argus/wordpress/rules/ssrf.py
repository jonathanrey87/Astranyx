import re

RULES = [
    {
        "category": "SSRF Sink",
        "severity": "Medium",
        "pattern": re.compile(r"wp_remote_get|wp_remote_post|curl_init|curl_exec|file_get_contents"),
    },
]
