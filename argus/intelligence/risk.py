WEIGHTS = {
    "Critical": 20,
    "High": 10,
    "Medium": 5,
    "Low": 2,
    "Info": 1,
}


def calculate(findings):
    score = 0

    for finding in findings:
        score += WEIGHTS.get(finding.severity, 1)

    return min(score, 100)


def rating(score):
    if score >= 90:
        return "Critical"

    if score >= 70:
        return "High"

    if score >= 40:
        return "Medium"

    if score >= 20:
        return "Low"

    return "Minimal"
