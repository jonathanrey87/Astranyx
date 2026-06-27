from pathlib import Path

REQUIRED_FILES = [
    "README.md",
    "notes.md",
    "timeline.md",
]

REQUIRED_DIRS = [
    "screenshots",
    "videos",
    "traffic",
    "requests",
    "responses",
    "artifacts",
]

def run(args):
    path = Path(args.path)

    if not path.exists():
        print(f"[-] Investigation not found: {path}")
        return 1

    print("ARGUS REVIEW")
    print("============")
    print(f"Target: {path}")
    print()

    score = 0
    total = len(REQUIRED_FILES) + len(REQUIRED_DIRS)

    print("Workspace Check")
    print("---------------")

    for file in REQUIRED_FILES:
        item = path / file
        if item.exists():
            print(f"✓ {file}")
            score += 1
        else:
            print(f"✗ {file}")

    for folder in REQUIRED_DIRS:
        item = path / folder
        if item.exists():
            print(f"✓ {folder}/")
            score += 1
        else:
            print(f"✗ {folder}/")

    confidence = int((score / total) * 100)

    print()
    print(f"Confidence: {confidence}%")

    if confidence < 60:
        print("Recommendation: NOT READY")
    elif confidence < 90:
        print("Recommendation: NEEDS MORE EVIDENCE")
    else:
        print("Recommendation: READY FOR MANUAL REVIEW")

    return 0
