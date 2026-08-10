from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterable
from pathlib import Path

from astranyx.models.ir import IRModule


class BaseParser(ABC):
    """
    Common interface implemented by all Astranyx language parsers.
    """

    language: str = "unknown"
    extensions: tuple[str, ...] = ()

    def supports(self, path: Path) -> bool:
        return path.suffix.lower() in self.extensions

    @abstractmethod
    def parse_file(self, path: Path) -> IRModule:
        """
        Parse one source file and return a language-neutral IR module.
        """
        raise NotImplementedError

    def parse_paths(self, paths: Iterable[Path]) -> list[IRModule]:
        modules: list[IRModule] = []

        for path in paths:
            if path.is_file() and self.supports(path):
                modules.append(self.parse_file(path))

        return modules
