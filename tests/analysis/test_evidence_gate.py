import pytest

from argus.analysis.evidence_gate import EvidenceGate, FindingEvidence


@pytest.fixture
def gate():
    return EvidenceGate()


@pytest.mark.parametrize(
    ("category", "evidence"),
    [
        ("pii", FindingEvidence(category="pii", sensitive_value="")),
        ("crlf", FindingEvidence(category="crlf", injected_header=False)),
        (
            "cors",
            FindingEvidence(
                category="cors",
                attacker_origin_readable=True,
                authenticated_sensitive_data=False,
            ),
        ),
        ("http_500", FindingEvidence(category="http_500")),
        ("graphql", FindingEvidence(category="graphql", protected_data=False)),
        ("health", FindingEvidence(category="health")),
    ],
)
def test_rejects_findings_without_impact(gate, category, evidence):
    decision = gate.evaluate(evidence)

    assert decision.reportable is False
    assert decision.reason


def test_accepts_nonempty_pii(gate):
    decision = gate.evaluate(
        FindingEvidence(category="pii", sensitive_value="private-value")
    )

    assert decision.reportable is True


def test_accepts_actual_header_injection(gate):
    decision = gate.evaluate(
        FindingEvidence(category="crlf", injected_header=True)
    )

    assert decision.reportable is True


def test_rejects_same_domain_redirect(gate):
    decision = gate.evaluate(
        FindingEvidence(
            category="open_redirect",
            final_url="https://login.instagram.com/path",
            trusted_hosts=("instagram.com",),
        )
    )

    assert decision.reportable is False


def test_accepts_external_redirect(gate):
    decision = gate.evaluate(
        FindingEvidence(
            category="open_redirect",
            final_url="https://example.net/path",
            trusted_hosts=("instagram.com",),
        )
    )

    assert decision.reportable is True


def test_accepts_cors_with_sensitive_authenticated_data(gate):
    decision = gate.evaluate(
        FindingEvidence(
            category="cors",
            attacker_origin_readable=True,
            authenticated_sensitive_data=True,
        )
    )

    assert decision.reportable is True


def test_accepts_server_error_with_data_exposure(gate):
    decision = gate.evaluate(
        FindingEvidence(category="http_500", data_exposure=True)
    )

    assert decision.reportable is True


def test_accepts_graphql_protected_data(gate):
    decision = gate.evaluate(
        FindingEvidence(category="graphql", protected_data=True)
    )

    assert decision.reportable is True
