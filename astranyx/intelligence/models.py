from dataclasses import dataclass, field


@dataclass
class EvidenceCategory:
    """Represents one category of investigation evidence."""

    name: str
    matches: int = 0
    bundles: list[str] = field(default_factory=list)
    routes: list[str] = field(default_factory=list)
    services: list[str] = field(default_factory=list)

    risk: str = "Unknown"
    confidence: int = 0

    notes: list[str] = field(default_factory=list)


@dataclass
class InvestigationSummary:
    """High-level summary used by the report engine."""

    target: str
    files_analyzed: int

    categories: list[EvidenceCategory] = field(default_factory=list)

    generated: str = ""
