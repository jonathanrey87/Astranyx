"""Optional, evidence-grounded AI investigation pipeline stage."""

from astranyx.ai.investigator import AIInvestigator
from astranyx.ai.privacy import (
    EvidenceReleaseDenied,
    require_synthetic_finding,
)
from astranyx.analysis.pipeline import AnalysisStage


class AIInvestigationStage(AnalysisStage):
    """Investigate explicitly synthetic findings without blocking analysis."""

    name = "ai_investigation"

    def __init__(
        self,
        provider,
        *,
        input_key="ai_findings",
        output_key="ai_investigations",
    ):
        self.investigator = AIInvestigator(provider)
        self.input_key = input_key
        self.output_key = output_key

    def run(self, context: dict) -> None:
        findings = context.get(self.input_key, [])
        investigations = []
        errors = []

        for index, finding in enumerate(findings):
            try:
                safe_finding = require_synthetic_finding(finding)
                result = self.investigator.analyze(safe_finding)
                investigations.append(result)

            except EvidenceReleaseDenied as exc:
                errors.append(
                    {
                        "index": index,
                        "type": "privacy",
                        "message": str(exc),
                    }
                )

            except Exception as exc:  # noqa: BLE001
                errors.append(
                    {
                        "index": index,
                        "type": "provider",
                        "message": type(exc).__name__,
                    }
                )

        context[self.output_key] = investigations
        context["ai_investigation_errors"] = errors
