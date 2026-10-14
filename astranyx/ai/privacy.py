"""Explicit data-release gate for external AI providers."""


class EvidenceReleaseDenied(ValueError):
    pass


def require_synthetic_finding(finding):
    if not isinstance(finding, dict):
        raise EvidenceReleaseDenied("Expected a dictionary")

    if finding.get("data_classification") != "synthetic":
        raise EvidenceReleaseDenied(
            "External AI requires explicitly classified synthetic data"
        )

    allowed = {
        "category",
        "severity",
        "evidence",
        "reason",
        "fingerprint",
    }

    return {key: finding[key] for key in allowed if key in finding}
