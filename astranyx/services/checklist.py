from pathlib import Path

CHECKLIST = """# Investigation Checklist

## Environment
- [ ] Device connected
- [ ] iOS version recorded
- [ ] App version recorded

## Authentication
- [ ] Logged out
- [ ] Logged in
- [ ] Expired session

## Deep Links
- [ ] Valid link
- [ ] Invalid link
- [ ] Unauthorized access

## Evidence
- [ ] Screenshots
- [ ] Requests
- [ ] Responses
- [ ] Timeline updated
"""


def create(workspace):
    workspace = Path(workspace)
    checklist = workspace / "checklist.md"

    if not checklist.exists():
        checklist.write_text(CHECKLIST)

    return checklist
