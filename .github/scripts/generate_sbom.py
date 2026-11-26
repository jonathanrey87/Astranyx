"""Validate and normalize Astranyx runtime SBOMs."""

import argparse
import hashlib
import json
import tomllib
from pathlib import Path

from cyclonedx.schema import SchemaVersion
from cyclonedx.validation.json import JsonStrictValidator
from packageurl import PackageURL
from packaging.utils import canonicalize_name, parse_wheel_filename


def require(condition, message):
    if not condition:
        raise ValueError(message)


def normalize_sbom(data, project, wheel, platform):
    require(data["bomFormat"] == "CycloneDX", "Invalid BOM format")
    require(data["specVersion"] == "1.6", "Invalid specification")

    root = data["metadata"]["component"]
    name = canonicalize_name(project["name"])
    version = project["version"]

    require(
        canonicalize_name(root["name"]) == name,
        "Application name mismatch",
    )
    require(root["version"] == version, "Application version mismatch")
    require(root["type"] == "application", "Invalid application type")

    wheel_name, wheel_version, _, _ = parse_wheel_filename(wheel.name)

    require(wheel_name == name, "Wheel name mismatch")
    require(str(wheel_version) == version, "Wheel version mismatch")

    require(
        platform in {"linux", "windows"},
        "Unsupported platform",
    )

    expected = {} if platform == "linux" else {"pywin32": "312"}

    components = data.get("components", [])
    observed = {}

    for component in components:
        key = canonicalize_name(component["name"])
        require(key not in observed, "Duplicate runtime component")
        observed[key] = component["version"]

    require(observed == expected, "Runtime inventory mismatch")

    root_ref = root["bom-ref"]
    component_refs = [item["bom-ref"] for item in components]
    refs = {root_ref, *component_refs}

    require(
        len(refs) == len(components) + 1,
        "Duplicate component reference",
    )

    graph = {}

    for entry in data.get("dependencies", []):
        ref = entry["ref"]

        require(ref in refs, "Unknown dependency reference")
        require(ref not in graph, "Duplicate dependency entry")

        targets = entry.get("dependsOn", [])

        require(
            len(targets) == len(set(targets)),
            "Duplicate dependency target",
        )
        require(set(targets) <= refs, "Unknown dependency target")

        graph[ref] = set(targets)

    require(set(graph) == refs, "Incomplete dependency graph")
    require(
        graph[root_ref] == set(component_refs),
        "Application dependency graph mismatch",
    )

    for ref in component_refs:
        require(not graph[ref], "Unexpected transitive dependency")

    root["purl"] = PackageURL(
        type="pypi",
        name=name,
        version=version,
    ).to_string()

    with wheel.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()

    root["hashes"] = [{"alg": "SHA-256", "content": digest}]

    for component in components:
        component["purl"] = PackageURL(
            type="pypi",
            name=canonicalize_name(component["name"]),
            version=component["version"],
        ).to_string()

    data["components"] = components

    data["dependencies"] = [
        {"ref": ref, "dependsOn": sorted(targets)}
        for ref, targets in sorted(graph.items())
    ]

    return data


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--wheel", type=Path, required=True)
    parser.add_argument("--pyproject", type=Path, required=True)
    parser.add_argument(
        "--platform",
        choices=["linux", "windows"],
        required=True,
    )

    args = parser.parse_args()

    project = tomllib.loads(args.pyproject.read_text(encoding="utf-8"))["project"]

    data = json.loads(args.input.read_text(encoding="utf-8"))

    normalized = normalize_sbom(data, project, args.wheel, args.platform)

    content = json.dumps(normalized, indent=2, sort_keys=True) + "\n"

    validator = JsonStrictValidator(SchemaVersion.V1_6)
    errors = validator.validate_str(content)

    if errors:
        raise SystemExit(f"CycloneDX validation failed: {errors}")

    with args.output.open("x", encoding="utf-8", newline="\n") as stream:
        stream.write(content)

    print(f"Platform: {args.platform}")
    print(f"SBOM: {args.output}")
    print("SBOM normalization and validation: PASSED")


if __name__ == "__main__":
    main()
