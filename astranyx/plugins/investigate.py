from types import SimpleNamespace

from astranyx.plugins import focus, threat
from astranyx.services.checklist import create as create_checklist
from astranyx.services.data import load_apps


def run(args):
    print("ASTRANYX INVESTIGATION")
    print("===================")
    print()

    try:
        data = load_apps(args.metadata)
    except (OSError, ValueError) as e:
        print("[-] Metadata load failed")
        print(e)
        return 1

    app = data.get(args.bundle_id)

    if not app:
        print(f"[-] Bundle ID not found: {args.bundle_id}")
        return 1

    name = app.get("CFBundleDisplayName") or app.get("CFBundleName") or args.bundle_id

    print("Target")
    print("------")
    print(f"Name      : {name}")
    print(f"Bundle ID : {args.bundle_id}")
    print(f"Metadata  : {args.metadata}")
    print()
    print("✓ Metadata loaded")
    print()
    from astranyx.plugins.evidence import create_workspace

    workspace = create_workspace(f"INV {name}")

    print("Workspace")
    print("----------")
    print(workspace)

    checklist = create_checklist(workspace)
    print()
    print("Checklist")
    print("---------")
    print(checklist)
    print()

    print("Next")
    print("----")
    print(". Generate threat model")
    print(". Generate focus report")
    print(". Recommend playbooks")
    print()
    print("Running Analysis")
    print("----------------")

    analysis_args = SimpleNamespace(
        bundle=args.bundle_id,
        file=args.metadata,
    )

    print("[1/2] Threat model")
    threat.run(analysis_args)

    print()
    print("[2/2] Focus report")
    focus.run(analysis_args)

    print()
    print("Investigate Ready")
    print("-----------------")
    print("✓ Workspace")
    print("✓ Checklist")
    print("✓ Threat Model")
    print("✓ Focus Report")
    print("✓ Playbooks")

    return 0
