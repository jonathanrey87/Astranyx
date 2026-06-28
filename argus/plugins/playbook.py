from pathlib import Path

PLAYBOOK_DIR = Path("playbooks")

def run(args):
    name = args.name.lower().replace("-", "_")
    path = PLAYBOOK_DIR / f"{name}.md"

    if not path.exists():
        print(f"[-] Playbook not found: {name}")
        print()
        print("Available playbooks:")
        if PLAYBOOK_DIR.exists():
            for item in sorted(PLAYBOOK_DIR.glob("*.md")):
                print(f"- {item.stem}")
        return 1

    print(path.read_text())
    return 0
