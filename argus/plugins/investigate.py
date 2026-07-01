from argus.services.data import load_apps


def run(args):
    print("ARGUS INVESTIGATION")
    print("===================")
    print()

    try:
        data = load_apps(args.metadata)
    except Exception as e:
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
    print("Next:")
    print("- Generate threat model")
    print("- Generate focus report")
    print("- Create evidence workspace")
    print("- Recommend playbooks")

    return 0
