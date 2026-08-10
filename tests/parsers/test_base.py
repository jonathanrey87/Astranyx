from pathlib import Path

from astranyx.models.ir import IRModule
from astranyx.parsers.base import BaseParser


class DummyParser(BaseParser):
    language = "dummy"
    extensions = (".dum",)

    def parse_file(self, path: Path) -> IRModule:
        return IRModule.from_path(path, self.language)


def test_supports_expected_extension():
    parser = DummyParser()

    assert parser.supports(Path("sample.dum"))
    assert not parser.supports(Path("sample.rb"))


def test_parse_paths_filters_unsupported_files(tmp_path):
    supported = tmp_path / "one.dum"
    unsupported = tmp_path / "two.txt"

    supported.write_text("x")
    unsupported.write_text("y")

    parser = DummyParser()
    modules = parser.parse_paths([supported, unsupported])

    assert len(modules) == 1
    assert modules[0].language == "dummy"
    assert modules[0].path == str(supported)
