from pathlib import Path

REQUIRED_DIRS = [
    "screenshots",
    "videos",
    "traffic",
    "requests",
    "responses",
    "artifacts",
]


def get_status(workspace):
    workspace = Path(workspace)

    if not workspace.exists():
        return "MISSING"

    score = 0

    for d in REQUIRED_DIRS:
        p = workspace / d
        if p.exists() and any(p.iterdir()):
            score += 1

    if score == 0:
        return "DO NOT SUBMIT"

    if score < len(REQUIRED_DIRS):
        return "CONTINUE INVESTIGATION"

    return "READY FOR REVIEW"
