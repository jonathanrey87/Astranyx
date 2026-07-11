from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable


@dataclass(slots=True)
class ValidationEvidence:
    validator: str
    category: str
    confidence: float


class ValidationEngine:
    """
    Detects observable validation routines.
    It records evidence rather than deciding whether code is safe.
    """

    DEFAULT_VALIDATORS = {
        "validate": "Validation",
        "sanitize": "Sanitization",
        "escape": "Output Encoding",
        "allowlist": "Allowlist",
        "whitelist": "Allowlist",
        "normalize": "Normalization",
        "verify": "Verification",
        "authorize": "Authorization",
        "authenticate": "Authentication",
        "check_permission": "Authorization",
    }

    def __init__(self, validators=None):
        self.validators = validators or self.DEFAULT_VALIDATORS

    def analyze(self, calls: Iterable[str]) -> list[ValidationEvidence]:
        findings = []

        for call in calls:
            lowered = call.lower()

            for keyword, category in self.validators.items():
                if keyword in lowered:
                    findings.append(
                        ValidationEvidence(
                            validator=call,
                            category=category,
                            confidence=0.95,
                        )
                    )

        return findings
