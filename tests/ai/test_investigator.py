import json

from astranyx.ai.investigator import AIInvestigator


class MockProvider:
    def generate(self, prompt):
        assert "authorization" in prompt

        return json.dumps(
            {
                "summary": "Possible authorization weakness",
                "impact": "Unauthorized access requires verification",
                "next_step": "Compare authorized and unauthorized responses",
            }
        )


def test_ai_investigator():
    finding = {
        "category": "authorization",
        "severity": "high",
        "evidence": "Different users receive identical protected responses",
        "reason": "Potential missing ownership check",
        "fingerprint": "asx-demo-001",
    }

    result = AIInvestigator(MockProvider()).analyze(finding)

    assert result["finding_fingerprint"] == "asx-demo-001"
    assert result["ai_verified"] is False
    assert result["requires_validation"] is True
    assert "authorization" in result["summary"]
