"""Security regression tests for SBOM validation."""

import hashlib
import importlib.util
from pathlib import Path

import pytest

pytest.importorskip("cyclonedx")
pytest.importorskip("packageurl")
pytest.importorskip("packaging")

SCRIPT = (
    Path(__file__).resolve().parents[1] / ".github" / "scripts" / "generate_sbom.py"
)

spec = importlib.util.spec_from_file_location("generate_sbom", SCRIPT)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


@pytest.fixture
def project():
    return {
        "name": "astranyx-engine",
        "version": "4.0.0a7",
    }


@pytest.fixture
def wheel(tmp_path):
    path = tmp_path / ("astranyx_engine-4.0.0a7-py3-none-any.whl")
    path.write_bytes(b"synthetic wheel fixture")
    return path


@pytest.fixture
def bom():
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "name": "astranyx-engine",
                "version": "4.0.0a7",
                "bom-ref": "root-component",
            }
        },
        "components": [],
        "dependencies": [{"ref": "root-component"}],
    }


def windows_component():
    return {
        "type": "library",
        "name": "pywin32",
        "version": "312",
        "bom-ref": "pywin32",
    }


def configure_windows(bom):
    bom["components"] = [windows_component()]
    bom["dependencies"] = [
        {
            "ref": "root-component",
            "dependsOn": ["pywin32"],
        },
        {"ref": "pywin32"},
    ]


def test_valid_linux(bom, project, wheel):
    result = module.normalize_sbom(bom, project, wheel, "linux")

    root = result["metadata"]["component"]

    assert root["purl"] == ("pkg:pypi/astranyx-engine@4.0.0a7")

    assert root["hashes"] == [
        {
            "alg": "SHA-256",
            "content": hashlib.sha256(wheel.read_bytes()).hexdigest(),
        }
    ]

    assert result["components"] == []
    assert result["dependencies"] == [
        {
            "ref": "root-component",
            "dependsOn": [],
        }
    ]


def test_valid_windows(bom, project, wheel):
    configure_windows(bom)

    result = module.normalize_sbom(bom, project, wheel, "windows")

    assert result["components"][0]["purl"] == ("pkg:pypi/pywin32@312")


@pytest.mark.parametrize(
    "scenario",
    [
        "wrong-format",
        "wrong-specification",
        "wrong-name",
        "wrong-version",
        "wrong-type",
        "unexpected-component",
        "missing-root",
        "duplicate-root",
        "unknown-reference",
        "unknown-target",
        "duplicate-target",
        "self-dependency",
        "unsupported-platform",
        "wrong-wheel-name",
        "wrong-wheel-version",
    ],
)
def test_reject_invalid_linux(bom, project, wheel, scenario):
    root = bom["metadata"]["component"]
    platform = "linux"

    if scenario == "wrong-format":
        bom["bomFormat"] = "SPDX"
    elif scenario == "wrong-specification":
        bom["specVersion"] = "1.5"
    elif scenario == "wrong-name":
        root["name"] = "wrong-package"
    elif scenario == "wrong-version":
        root["version"] = "9.9.9"
    elif scenario == "wrong-type":
        root["type"] = "library"
    elif scenario == "unexpected-component":
        bom["components"].append(windows_component())
    elif scenario == "missing-root":
        bom["dependencies"] = []
    elif scenario == "duplicate-root":
        bom["dependencies"].append({"ref": "root-component"})
    elif scenario == "unknown-reference":
        bom["dependencies"].append({"ref": "unknown"})
    elif scenario == "unknown-target":
        bom["dependencies"][0]["dependsOn"] = ["unknown"]
    elif scenario == "duplicate-target":
        bom["dependencies"][0]["dependsOn"] = [
            "root-component",
            "root-component",
        ]
    elif scenario == "self-dependency":
        bom["dependencies"][0]["dependsOn"] = ["root-component"]
    elif scenario == "unsupported-platform":
        platform = "darwin"
    elif scenario == "wrong-wheel-name":
        wheel = wheel.rename(wheel.with_name("wrong_package-4.0.0a7-py3-none-any.whl"))
    elif scenario == "wrong-wheel-version":
        wheel = wheel.rename(wheel.with_name("astranyx_engine-9.9.9-py3-none-any.whl"))

    with pytest.raises(ValueError):
        module.normalize_sbom(bom, project, wheel, platform)


@pytest.mark.parametrize(
    "scenario",
    [
        "missing-pywin32",
        "wrong-pywin32-version",
        "duplicate-component",
        "duplicate-reference",
        "missing-dependency-edge",
        "missing-dependency-entry",
        "unexpected-transitive-dependency",
    ],
)
def test_reject_invalid_windows(bom, project, wheel, scenario):
    configure_windows(bom)

    if scenario == "missing-pywin32":
        bom["components"] = []
    elif scenario == "wrong-pywin32-version":
        bom["components"][0]["version"] = "311"
    elif scenario == "duplicate-component":
        bom["components"].append(windows_component())
    elif scenario == "duplicate-reference":
        bom["components"][0]["bom-ref"] = "root-component"
    elif scenario == "missing-dependency-edge":
        bom["dependencies"][0]["dependsOn"] = []
    elif scenario == "missing-dependency-entry":
        bom["dependencies"].pop()
    elif scenario == "unexpected-transitive-dependency":
        bom["dependencies"][1]["dependsOn"] = ["root-component"]

    with pytest.raises(ValueError):
        module.normalize_sbom(bom, project, wheel, "windows")
