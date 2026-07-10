from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass(slots=True)
class SourceLocation:
    file: str
    line: int
    column: int = 1


@dataclass(slots=True)
class IRVariable:
    name: str
    location: SourceLocation
    kind: str = "local"
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class IRCall:
    target: str
    location: SourceLocation
    arguments: list[str] = field(default_factory=list)
    receiver: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class IRFunction:
    name: str
    location: SourceLocation
    parameters: list[str] = field(default_factory=list)
    calls: list[IRCall] = field(default_factory=list)
    variables: list[IRVariable] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class IRClass:
    name: str
    location: SourceLocation
    methods: list[IRFunction] = field(default_factory=list)
    bases: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class IRModule:
    path: str
    language: str
    functions: list[IRFunction] = field(default_factory=list)
    classes: list[IRClass] = field(default_factory=list)
    imports: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_path(cls, path: Path, language: str) -> "IRModule":
        return cls(path=str(path), language=language)
