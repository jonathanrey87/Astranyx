from astranyx.ai.dashboard import render_dashboard


def test_dashboard_renders_investigation():
    report = {
        "generated": "2026-10-14T14:16:07Z",
        "investigations": [
            {
                "finding_fingerprint": "asx-test-001",
                "summary": "Possible authorization weakness",
                "impact": "Potential data exposure",
                "next_step": "Validate with authorized accounts",
            }
        ],
        "errors": [],
    }

    html = render_dashboard(report)

    assert "ASTRANYX" in html
    assert "Investigation Overview" in html
    assert "asx-test-001" in html
    assert "AI ANALYSIS · UNVERIFIED" in html
    assert "AWAITING VALIDATION" in html


def test_dashboard_escapes_untrusted_evidence():
    report = {
        "investigations": [
            {
                "finding_fingerprint": "asx-test",
                "summary": "<script>alert(1)</script>",
                "impact": '<img src=x onerror="alert(1)">',
                "next_step": "Manual review",
            }
        ],
        "errors": [],
    }

    html = render_dashboard(report)

    assert "<script>alert(1)</script>" not in html
    assert '<img src=x onerror="alert(1)">' not in html
    assert "&lt;script&gt;" in html
    assert "&lt;img" in html
