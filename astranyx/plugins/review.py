import re
from pathlib import Path

REQUIRED_FILES = ["README.md", "notes.md", "timeline.md"]
REQUIRED_DIRS = [
    "screenshots",
    "videos",
    "traffic",
    "requests",
    "responses",
    "artifacts",
]

RESEARCH_FIELDS = {
    "Security Boundary": r"(?i)security boundary\s*\n\s*(?!\n|##)",
    "Impact": r"(?i)impact\s*\n\s*(?!\n|##)",
    "Reproduction Steps": r"(?i)reproduction steps\s*\n\s*(?!\n|##)",
    "Expected Behavior": r"(?i)expected behavior\s*\n\s*(?!\n|##)",
    "Observed Behavior": r"(?i)observed behavior\s*\n\s*(?!\n|##)",
}


def has_content(path: Path) -> bool:
    return path.exists() and path.is_file() and path.stat().st_size > 20


def count_files(path: Path) -> int:
    if not path.exists() or not path.is_dir():
        return 0
    return sum(1 for p in path.rglob("*") if p.is_file())


def field_present(text: str, pattern: str) -> bool:
    return re.search(pattern, text) is not None


def run(args):
    path = Path(args.path)

    if not path.exists():
        print(f"[-] Investigation not found: {path}")
        return 1

    readme = path / "README.md"
    notes = path / "notes.md"
    timeline = path / "timeline.md"

    score = 0
    total = 0

    print("ASTRANYX REVIEW v2")
    print("===============")
    print(f"Target: {path}")
    print()

    print("Workspace")
    print("---------")
    for file in REQUIRED_FILES:
        total += 1
        item = path / file
        if has_content(item):
            print(f"✓ {file}")
            score += 1
        else:
            print(f"✗ {file}")

    for folder in REQUIRED_DIRS:
        total += 1
        item = path / folder
        if item.exists() and item.is_dir():
            print(f"✓ {folder}/")
            score += 1
        else:
            print(f"✗ {folder}/")
    print()

    print("Evidence")
    print("--------")
    evidence_dirs = [
        "screenshots",
        "videos",
        "traffic",
        "requests",
        "responses",
        "artifacts",
    ]
    for folder in evidence_dirs:
        total += 1
        n = count_files(path / folder)
        if n > 0:
            print(f"✓ {folder}/ ({n} files)")
            score += 1
        else:
            print(f"✗ {folder}/ (empty)")
    print()

    combined_text = ""
    for f in [readme, notes, timeline]:
        if f.exists():
            combined_text += "\n" + f.read_text(errors="ignore")

    print("Research Quality")
    print("----------------")
    for label, pattern in RESEARCH_FIELDS.items():
        total += 1
        if field_present(combined_text, pattern):
            print(f"✓ {label}")
            score += 1
        else:
            print(f"✗ {label}")
    print()

    confidence = int((score / total) * 100) if total else 0

    print(f"Confidence: {confidence}%")

    if confidence < 50:
        print("Recommendation: DO NOT SUBMIT")
    elif confidence < 80:
        print("Recommendation: CONTINUE INVESTIGATION")
    else:
        print("Recommendation: READY FOR MANUAL REVIEW")

    return 0
