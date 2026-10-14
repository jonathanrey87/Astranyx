"""Tests for optional AI investigation pipeline integration."""

import json

from astranyx.ai.stage import AIInvestigationStage
from astranyx.analysis.pipeline import build_default_pipeline


class MockProvider:
    def generate(self, prompt):
        return json.dumps(
            {
                "summary": "Potential authorization weakness",
                "impact": "Possible cross-account exposure",
                "next_step": "Validate with authorized test accounts",
            }
        )


class FailingProvider:
    def generate(self, prompt):
        raise RuntimeError("Provider unavailable")


def synthetic_finding():
    return {
        "category": "authorization",
        "severity": "medium",
        "evidence": "Synthetic cross-account response mismatch",
        "reason": "Potential ownership check failure",
        "fingerprint": "asx-pipeline-001",
        "data_classification": "synthetic",
    }


def test_ai_stage_generates_investigation():
    context = {"ai_findings": [synthetic_finding()]}

    AIInvestigationStage(MockProvider()).run(context)

    assert len(context["ai_investigations"]) == 1
    assert context["ai_investigations"][0]["ai_verified"] is False
    assert context["ai_investigations"][0]["requires_validation"] is True
    assert context["ai_investigation_errors"] == []


def test_ai_stage_rejects_unclassified_evidence():
    finding = synthetic_finding()
    finding.pop("data_classification")

    context = {"ai_findings": [finding]}

    AIInvestigationStage(MockProvider()).run(context)

    assert context["ai_investigations"] == []
    assert context["ai_investigation_errors"][0]["type"] == "privacy"


def test_ai_stage_survives_provider_failure():
    context = {"ai_findings": [synthetic_finding()]}

    AIInvestigationStage(FailingProvider()).run(context)

    assert context["ai_investigations"] == []
    assert context["ai_investigation_errors"][0]["type"] == "provider"


def test_default_pipeline_remains_ai_free():
    pipeline = build_default_pipeline()

    assert all(stage.name != "ai_investigation" for stage in pipeline.stages)
