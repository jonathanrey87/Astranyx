from dataclasses import dataclass

from argus.intelligence.classify import classify
from argus.intelligence.models import EvidenceCategory
from argus.intelligence.recommendations import generate_recommendations
from argus.intelligence.scoring import calculate_score


@dataclass
class IntelligenceReport:
    categories: list[EvidenceCategory]
    recommendations: list[str]


def analyze_intelligence(report: dict) -> IntelligenceReport:

    categories = classify(
        report.get("summary", {}),
        report.get("routes", []),
    )

    for category in categories:
        assessment = calculate_score(
            category.name,
            category.matches,
        )

        category.risk = assessment.risk
        category.confidence = assessment.confidence
        category.notes.append(assessment.reason)

    recommendations = generate_recommendations(categories)

    return IntelligenceReport(
        categories=categories,
        recommendations=recommendations,
    )
