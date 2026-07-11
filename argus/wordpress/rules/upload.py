import re

RULES = [
    {
        "category": "Upload Handler",
        "severity": "High",
        "pattern": re.compile(
            r"move_uploaded_file|wp_handle_upload|media_handle_upload"
        ),
    },
]
