from pathlib import Path

PLAYBOOK_DIR = Path("playbooks")


def available_playbooks():
    if not PLAYBOOK_DIR.exists():
        return []
    return sorted(item.stem for item in PLAYBOOK_DIR.glob("*.md"))


def show_list():
    playbooks = available_playbooks()

    print("ASTRANYX PLAYBOOKS")
    print("================")
    print()

    if not playbooks:
        print("No playbooks found.")
        return 1

    for name in playbooks:
        print(f"- {name}")

    return 0


def show_playbook(name: str):
    normalized = name.lower().replace("-", "_")
    path = PLAYBOOK_DIR / f"{normalized}.md"

    if not path.exists():
        print(f"[-] Playbook not found: {normalized}")
        print()
        print("Available playbooks:")
        for item in available_playbooks():
            print(f"- {item}")
        return 1

    print(path.read_text())
    return 0


def run(args):
    if args.name == "list":
        return show_list()

    return show_playbook(args.name)
