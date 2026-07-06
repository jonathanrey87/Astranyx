"""
Argus Intelligence Engine
Risk scoring utilities.
"""

from dataclasses import dataclass


@dataclass
class RiskAssessment:
    category: str
    score: int
    risk: str
    confidence: int
    reason: str


WEIGHTS = {
    "authentication": 30,
    "auth": 30,
    "oauth": 20,
    "graphql": 20,
    "uploads": 30,
    "upload": 30,
    "admin": 25,
    "collaboration": 10,
    "network_fetch": 15,
}


def calculate_score(category: str, matches: int) -> RiskAssessment:
    """Calculate a simple explainable risk score."""

    weight = WEIGHTS.get(category.lower(), 10)

    score = min(100, weight + min(matches // 10, 70))

    if score >= 80:
        risk = "High"
    elif score >= 50:
        risk = "Medium"
    else:
        risk = "Low"

    confidence = min(100, 50 + matches // 5)

    return RiskAssessment(
        category=category,
        score=score,
        risk=risk,
        confidence=confidence,
        reason=f"{matches} evidence matches",
    )
