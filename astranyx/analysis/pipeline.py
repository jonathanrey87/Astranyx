
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class AnalysisResult:
    findings: list[Any] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


class AnalysisStage:
    """Base class for all Astranyx analysis stages."""

    name = "stage"

    def run(self, context: dict) -> None:
        raise NotImplementedError


class AnalysisPipeline:
    """Executes registered analysis stages in order."""

    def __init__(self):
        self.stages: list[AnalysisStage] = []

    def register(self, stage: AnalysisStage) -> None:
        self.stages.append(stage)

    def execute(self, context: dict) -> dict:
        for stage in self.stages:
            stage.run(context)

        return context


def build_default_pipeline(
    *,
    enable_ai: bool = False,
    provider=None,
) -> AnalysisPipeline:
    """
    Build the default Astranyx analysis pipeline.

    AI investigation is disabled by default.

    When enabled, an explicit provider must be supplied.
    The AI stage runs after the deterministic analysis stages.
    """

    # Local imports prevent circular dependencies.
    from astranyx.analysis.attack_surface import AttackSurfaceStage
    from astranyx.analysis.authorization import AuthorizationDifferentialStage
    from astranyx.analysis.evidence_gate import EvidenceGateStage

    pipeline = AnalysisPipeline()

    # Deterministic analysis stages
    pipeline.register(AuthorizationDifferentialStage())
    pipeline.register(EvidenceGateStage())
    pipeline.register(AttackSurfaceStage())

    # Optional AI investigation stage
    if enable_ai:
        if provider is None:
            raise ValueError(
                "An explicit AI provider is required when enable_ai=True"
            )

        from astranyx.ai.stage import AIInvestigationStage

        pipeline.register(AIInvestigationStage(provider))

    return pipeline

