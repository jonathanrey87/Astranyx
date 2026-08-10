import subprocess
from pathlib import Path

from astranyx.services.status import get_status


def git_value(cmd):
    try:
        return subprocess.check_output(cmd, text=True).strip()
    except (OSError, subprocess.SubprocessError):
        return "unknown"


def run(args):
    evidence_dir = Path("evidence")
    reports_dir = Path("reports")
    playbooks_dir = Path("playbooks")

    investigations = (
        sorted(p for p in evidence_dir.glob("INV_*") if p.is_dir())
        if evidence_dir.exists()
        else []
    )

    reports = sorted(reports_dir.glob("*.md")) if reports_dir.exists() else []
    playbooks = sorted(playbooks_dir.glob("*.md")) if playbooks_dir.exists() else []

    print("ASTRANYX DASHBOARD")
    print("===============")
    print()

    print("Project")
    print("-------")
    print(f"Branch : {git_value(['git', 'branch', '--show-current'])}")
    print(f"Commit : {git_value(['git', 'rev-parse', '--short', 'HEAD'])}")
    print()

    print("Inventory")
    print("---------")
    print(f"Investigations : {len(investigations)}")
    print(f"Reports        : {len(reports)}")
    print(f"Playbooks      : {len(playbooks)}")
    print()

    print("Investigations")
    print("--------------")
    if investigations:
        for item in investigations:
            status = get_status(item)
            print(f"- {item.name:<35} {status}")
    else:
        print("- none")

    return 0
