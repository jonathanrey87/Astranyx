from collections import Counter


def build_attack_surface(findings):
    counts = Counter()

    mapping = {
        "REST Route": "REST Routes",
        "Public REST Permission": "REST Routes",
        "AJAX Route": "AJAX Hooks",
        "Upload Handler": "Uploads",
        "SSRF Sink": "Remote HTTP",
        "SQL Query": "Database Queries",
        "React Dangerous Sink": "React Components",
        "DOM Sink": "DOM Components",
        "Dynamic Include": "Dynamic Includes",
        "Deserialization": "Deserialization",
        "Potential Taint Flow": "Taint Flows",
    }

    for finding in findings:
        category = mapping.get(finding.category)
        if category:
            counts[category] += 1

    return dict(sorted(counts.items()))
