from argus.intelligence.classify import classify
from argus.intelligence.scoring import calculate_score


def analyze_intelligence(report: dict) -> list:
    categories = classify(
        report.get("summary", {}),
        report.get("routes", []),
    )

    for category in categories:
        assessment = calculate_score(category.name, category.matches)
        category.risk = assessment.risk
        category.confidence = assessment.confidence
        category.notes.append(assessment.reason)

    return categories
