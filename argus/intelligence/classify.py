"""
Argus Intelligence Engine

Evidence classification.
"""

from argus.intelligence.models import EvidenceCategory


def classify(summary: dict, routes: list[str]) -> list[EvidenceCategory]:
    """
    Convert analyzer output into EvidenceCategory objects.
    """

    categories = {}

    # Aggregate bundle evidence
    for bundle, findings in summary.items():
        for category, matches in findings.items():

            if category not in categories:
                categories[category] = EvidenceCategory(name=category)

            evidence = categories[category]

            evidence.matches += matches
            evidence.bundles.append(bundle)

    # Associate routes
    for route in routes:

        lower = route.lower()

        for category, evidence in categories.items():

            if category in lower:
                evidence.routes.append(route)

            elif category == "auth" and any(
                x in lower for x in ("login", "logout", "session", "oauth")
            ):
                evidence.routes.append(route)

            elif category == "uploads" and any(
                x in lower for x in ("upload", "file", "files")
            ):
                evidence.routes.append(route)

    # Remove duplicates
    for evidence in categories.values():
        evidence.bundles = sorted(set(evidence.bundles))
        evidence.routes = sorted(set(evidence.routes))

    return list(categories.values())
