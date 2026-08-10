from __future__ import annotations

from dataclasses import dataclass, field

from astranyx.analysis.validation import ValidationEvidence
from astranyx.graph.dfg import DataFlowGraph
from astranyx.graph.trust import TrustEngine, TrustLevel


@dataclass(slots=True)
class TaintEvidence:
    source: str
    sink: str
    trust: TrustLevel
    validators: list[ValidationEvidence] = field(default_factory=list)


class TaintEngine:
    def __init__(self):
        self.trust = TrustEngine()

    def analyze(
        self,
        graph: DataFlowGraph,
        validations: list[ValidationEvidence],
    ) -> list[TaintEvidence]:

        findings: list[TaintEvidence] = []

        for source in graph.nodes:
            trust = self.trust.classify(source)

            if trust != TrustLevel.UNTRUSTED:
                continue

            for sink in graph.successors(source):
                findings.append(
                    TaintEvidence(
                        source=source,
                        sink=sink,
                        trust=trust,
                        validators=[v for v in validations if v.location == sink],
                    )
                )

        return findings
