import re

RULES = [
    {
        "category": "REST Route",
        "severity": "Info",
        "pattern": re.compile(r"register_rest_route\s*\("),
    },
    {
        "category": "Public REST Permission",
        "severity": "Medium",
        "pattern": re.compile(r"permission_callback.*__return_true"),
    },
]
