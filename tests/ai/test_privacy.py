import pytest

from astranyx.ai.privacy import (
    EvidenceReleaseDenied,
    require_synthetic_finding,
)


def test_real_evidence_blocked():
    with pytest.raises(EvidenceReleaseDenied):
        require_synthetic_finding({
            "category": "authorization",
            "evidence": "private customer data",
        })


def test_synthetic_evidence_allowed():
    result = require_synthetic_finding({
        "data_classification": "synthetic",
        "category": "authorization",
        "evidence": "fake laboratory finding",
        "private_token": "must-not-be-forwarded",
    })

    assert "private_token" not in result
    assert result["category"] == "authorization"
