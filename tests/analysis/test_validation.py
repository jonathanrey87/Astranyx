from astranyx.analysis.validation import ValidationEngine


def test_detects_validation():
    engine = ValidationEngine()

    findings = engine.analyze(
        [
            "normalize_url",
            "allowlist_host",
            "Gitlab::HTTP.get",
        ]
    )

    assert len(findings) == 2
    assert findings[0].category == "Normalization"
    assert findings[1].category == "Allowlist"


def test_no_validation():
    engine = ValidationEngine()

    findings = engine.analyze(
        [
            "Gitlab::HTTP.get",
            "puts",
        ]
    )

    assert findings == []
