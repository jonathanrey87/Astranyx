from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class AnalysisResult:
    findings: list[Any] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


class AnalysisStage:
    """
    Base class for all Orion analysis stages.
    """

    name = "stage"

    def run(self, context: dict) -> None:
        raise NotImplementedError


class AnalysisPipeline:

    def __init__(self):
        self.stages: list[AnalysisStage] = []

    def register(self, stage: AnalysisStage):
        self.stages.append(stage)

    def execute(self, context: dict):

        for stage in self.stages:
            stage.run(context)

        return context
