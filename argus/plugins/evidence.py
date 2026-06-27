from datetime import datetime
from pathlib import Path
import re

def slugify(name: str) -> str:
    clean = re.sub(r"[^A-Za-z0-9]+", "_", name.strip())
    return clean.strip("_") or "investigation"

def create_workspace(name: str) -> Path:
    slug = slugify(name)
    root = Path("evidence") / slug

    folders = [
        root,
        root / "screenshots",
        root / "videos",
        root / "traffic",
        root / "requests",
        root / "responses",
        root / "artifacts",
    ]

    for folder in folders:
        folder.mkdir(parents=True, exist_ok=True)

    started = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    (root / "README.md").write_text(f"""# Investigation: {name}

Status: In Progress

Started: {started}

Researcher: Jonathan Mendiola

## Target

## Scope

## Security Boundary

## Summary

""")

    (root / "notes.md").write_text("""# Notes

## Threat Model

## Attack Surface

## Observations

## Questions

## Evidence

""")

    (root / "timeline.md").write_text(f"""# Timeline

- {started} — Investigation workspace created.

""")

    return root

def run(args):
    if args.evidence_command == "create":
        path = create_workspace(args.name)
        print("[+] Evidence workspace created")
        print(f"[+] Path: {path}")
        return 0

    print("Usage: argus evidence create <name>")
    return 1
