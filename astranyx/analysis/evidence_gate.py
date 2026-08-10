from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import urlparse

from astranyx.analysis.pipeline import AnalysisStage


@dataclass(slots=True)
class FindingEvidence:
    category: str
    sensitive_value: str = ""
    injected_header: bool = False
    final_url: str = ""
    trusted_hosts: tuple[str, ...] = field(default_factory=tuple)
    attacker_origin_readable: bool = False
    authenticated_sensitive_data: bool = False
    stack_trace: bool = False
    data_exposure: bool = False
    authorization_impact: bool = False
    availability_impact: bool = False
    protected_data: bool = False


@dataclass(slots=True)
class EvidenceDecision:
    reportable: bool
    reason: str


class EvidenceGate:
    """Rejects findings that lack observable security impact."""

    def evaluate(self, evidence: FindingEvidence) -> EvidenceDecision:
        category = evidence.category.lower().replace("-", "_").replace(" ", "_")

        if category in {"pii", "pii_disclosure"}:
            if evidence.sensitive_value.strip():
                return EvidenceDecision(
                    True,
                    "Non-empty sensitive value observed",
                )
            return EvidenceDecision(
                False,
                "No sensitive value was disclosed",
            )

        if category in {"crlf", "header_injection"}:
            if evidence.injected_header:
                return EvidenceDecision(
                    True,
                    "A separate response header was injected",
                )
            return EvidenceDecision(
                False,
                "Input was escaped or reflected only as text",
            )

        if category == "open_redirect":
            host = urlparse(evidence.final_url).hostname

            if host and not self._trusted(host, evidence.trusted_hosts):
                return EvidenceDecision(
                    True,
                    "Redirect left the trusted domain",
                )

            return EvidenceDecision(
                False,
                "Redirect remained on a trusted domain",
            )

        if category == "cors":
            if (
                evidence.attacker_origin_readable
                and evidence.authenticated_sensitive_data
            ):
                return EvidenceDecision(
                    True,
                    "Attacker origin read authenticated sensitive data",
                )

            return EvidenceDecision(
                False,
                "No cross-origin authenticated data exposure demonstrated",
            )

        if category in {"http_500", "server_error"}:
            impact = any(
                (
                    evidence.stack_trace,
                    evidence.data_exposure,
                    evidence.authorization_impact,
                    evidence.availability_impact,
                )
            )

            if impact:
                return EvidenceDecision(
                    True,
                    "Server error had security impact",
                )

            return EvidenceDecision(
                False,
                "Generic server error without impact",
            )

        if category == "graphql":
            if evidence.protected_data:
                return EvidenceDecision(
                    True,
                    "Unauthorized protected data returned",
                )

            return EvidenceDecision(
                False,
                "Query execution returned no protected data",
            )

        if category in {"health", "health_endpoint"}:
            if evidence.data_exposure or evidence.sensitive_value.strip():
                return EvidenceDecision(
                    True,
                    "Health endpoint exposed sensitive data",
                )

            return EvidenceDecision(
                False,
                "Health endpoint exposed status only",
            )

        return EvidenceDecision(
            False,
            "Manual validation required",
        )

    @staticmethod
    def _trusted(
        host: str,
        trusted_hosts: tuple[str, ...],
    ) -> bool:
        host = host.lower().rstrip(".")

        return any(
            host == trusted.lower().rstrip(".")
            or host.endswith("." + trusted.lower().rstrip("."))
            for trusted in trusted_hosts
        )


class EvidenceGateStage(AnalysisStage):
    """Applies evidence decisions within an AnalysisPipeline."""

    name = "evidence_gate"

    def __init__(
        self,
        gate: EvidenceGate | None = None,
        input_key: str = "finding_evidence",
        output_key: str = "evidence_decisions",
    ):
        self.gate = gate or EvidenceGate()
        self.input_key = input_key
        self.output_key = output_key

    def run(self, context: dict) -> None:
        records = context.get(self.input_key, [])
        decisions: list[EvidenceDecision] = []

        for record in records:
            if isinstance(record, FindingEvidence):
                evidence = record
            elif isinstance(record, dict):
                evidence = FindingEvidence(**record)
            else:
                raise TypeError(
                    "EvidenceGateStage records must be "
                    "FindingEvidence instances or dictionaries"
                )

            decisions.append(self.gate.evaluate(evidence))

        context[self.output_key] = decisions
        context["reportable_findings"] = sum(
            decision.reportable for decision in decisions
        )
