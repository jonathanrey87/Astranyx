"""
Astranyx Intelligence Engine

Generate investigation recommendations from classified evidence.
"""

from astranyx.intelligence.models import EvidenceCategory

RULES = {
    "auth": [
        "Review login and logout flows.",
        "Inspect session management.",
        "Verify authentication bypass protections.",
    ],
    "authentication": [
        "Review login and logout flows.",
        "Inspect session management.",
        "Verify authentication bypass protections.",
    ],
    "oauth": [
        "Review OAuth implementation.",
        "Validate redirect URI handling.",
        "Inspect token lifecycle and refresh flow.",
    ],
    "uploads": [
        "Review file upload validation.",
        "Verify MIME type validation.",
        "Inspect authorization on upload endpoints.",
    ],
    "upload": [
        "Review file upload validation.",
        "Verify MIME type validation.",
        "Inspect authorization on upload endpoints.",
    ],
    "graphql": [
        "Review GraphQL mutations.",
        "Inspect authorization checks.",
        "Look for introspection exposure.",
    ],
    "admin": [
        "Review administrator functionality.",
        "Verify privilege enforcement.",
        "Inspect administrative API endpoints.",
    ],
}


def generate_recommendations(
    categories: list[EvidenceCategory],
) -> list[str]:
    """
    Generate a prioritized recommendation list.
    """

    recommendations = []

    ranked = sorted(
        categories,
        key=lambda c: (c.confidence, c.matches),
        reverse=True,
    )

    for category in ranked:
        key = category.name.lower()

        if key in RULES:
            recommendations.extend(RULES[key])

    # Remove duplicates while preserving order
    seen = set()
    result = []

    for item in recommendations:
        if item not in seen:
            seen.add(item)
            result.append(item)

    return result
