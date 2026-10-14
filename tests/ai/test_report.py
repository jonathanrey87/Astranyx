import json

from astranyx.ai.report import (
    build_ai_report,
    write_ai_html,
    write_ai_json,
)


def test_ai_report_is_unverified():
    context = {
        "ai_investigations": [
            {
                "finding_fingerprint": "asx-demo",
                "summary": "Possible authorization weakness",
                "impact": "Potential cross-account access",
                "next_step": "Validate with authorized accounts",
                "ai_verified": True,
                "requires_validation": False,
            }
        ],
    }

    report = build_ai_report(context)

    assert report["verification_status"] == "unverified"
    assert report["investigations"][0]["ai_verified"] is False
    assert report["investigations"][0]["requires_validation"] is True


def test_ai_report_writes_json(tmp_path):
    report = build_ai_report({"ai_investigations": []})
    path = write_ai_json(report, tmp_path / "ai-investigation.json")

    loaded = json.loads(path.read_text(encoding="utf-8"))
    assert loaded["report_type"] == "astranyx_ai_investigation"


def test_ai_html_escapes_untrusted_content(tmp_path):
    context = {
        "ai_investigations": [
            {
                "finding_fingerprint": "asx-test",
                "summary": '<script>alert("xss")</script>',
                "impact": "<img src=x onerror=alert(1)>",
                "next_step": "Manual validation",
            }
        ],
    }

    report = build_ai_report(context)
    path = write_ai_html(report, tmp_path / "ai-investigation.html")
    html = path.read_text(encoding="utf-8")

    assert '<script>alert("xss")</script>' not in html
    assert "<img src=x onerror=alert(1)>" not in html
    assert "&lt;script&gt;" in html


def test_ai_report_omits_provider_error_details():
    report = build_ai_report(
        {
            "ai_investigation_errors": [
                {
                    "index": 0,
                    "type": "provider",
                    "message": "secret internal token",
                }
            ],
        }
    )

    serialized = json.dumps(report)
    assert "secret internal token" not in serialized
