from argus.analysis.taint import TaintEngine
from argus.analysis.validation import ValidationEvidence
from argus.graph.dfg import DataFlowGraph


def test_simple_taint():

    graph = DataFlowGraph()

    graph.add_edge(
        "params[:url]",
        "Gitlab::HTTP.get",
    )

    validations = [
        ValidationEvidence(
            validator="validate_url",
            location="Gitlab::HTTP.get",
            confidence=0.9,
            category="URL Validation",
        )
    ]

    findings = TaintEngine().analyze(
        graph,
        validations,
    )

    assert len(findings) == 1

    finding = findings[0]

    assert finding.source == "params[:url]"
    assert finding.sink == "Gitlab::HTTP.get"

    assert len(finding.validators) == 1
