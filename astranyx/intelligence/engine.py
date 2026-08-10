from dataclasses import dataclass

from astranyx.intelligence.classify import classify
from astranyx.intelligence.models import EvidenceCategory
from astranyx.intelligence.recommendations import generate_recommendations
from astranyx.intelligence.scoring import calculate_score


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
