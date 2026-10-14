"""Tests for explicit AI pipeline registration."""

import json

import pytest

from astranyx.analysis.pipeline import build_default_pipeline


class MockProvider:
    def generate(self, prompt):
        return json.dumps(
            {
                "summary": "Potential authorization weakness",
                "impact": "Possible cross-account exposure",
                "next_step": "Validate using authorized test accounts",
            }
        )


def test_ai_disabled_by_default():
    pipeline = build_default_pipeline()

    assert "ai_investigation" not in [stage.name for stage in pipeline.stages]


def test_ai_requires_provider():
    with pytest.raises(ValueError):
        build_default_pipeline(enable_ai=True)


def test_ai_stage_registered_last():
    pipeline = build_default_pipeline(
        enable_ai=True,
        provider=MockProvider(),
    )

    assert pipeline.stages[-1].name == "ai_investigation"


def test_ai_stage_executes_with_pipeline():
    pipeline = build_default_pipeline(
        enable_ai=True,
        provider=MockProvider(),
    )

    context = {
        "ai_findings": [
            {
                "category": "authorization",
                "severity": "medium",
                "evidence": "Synthetic ownership-check mismatch",
                "reason": "Potential missing authorization",
                "fingerprint": "asx-optin-001",
                "data_classification": "synthetic",
            }
        ],
    }

    result = pipeline.execute(context)

    assert result["ai_investigations"][0]["ai_verified"] is False
    assert result["ai_investigations"][0]["requires_validation"] is True
    assert result["ai_investigation_errors"] == []
