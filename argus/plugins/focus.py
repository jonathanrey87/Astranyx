from pathlib import Path

from argus.services.data import load_apps


def get_url_schemes(app):
    schemes = []
    for entry in app.get("CFBundleURLTypes", []) or []:
        schemes.extend(entry.get("CFBundleURLSchemes", []) or [])
    return sorted(set(schemes))


def run(args):
    target = Path(args.file)

    if not target.exists():
        print(f"[-] File not found: {target}")
        return 1

    data = load_apps(args.file)

    app = data.get(args.bundle)

    if app is None:
        print(f"[-] Bundle ID not found: {args.bundle}")
        return 1

    ent = app.get("Entitlements", {}) or {}

    print("ARGUS FOCUS REPORT")
    print("==================")
    print()

    print(
        f"Name: {app.get('CFBundleDisplayName') or app.get('CFBundleName') or args.bundle}"
    )
    print(f"Bundle ID: {args.bundle}")
    print()

    print("Attack Surface")
    print("--------------")

    if get_url_schemes(app):
        print("✓ URL Schemes")

    if ent.get("com.apple.developer.associated-domains"):
        print("✓ Universal Links")

    if ent.get("com.apple.developer.in-app-payments"):
        print("✓ Apple Pay")

    if ent.get("aps-environment"):
        print("✓ Push Notifications")

    if app.get("UIBackgroundModes"):
        print("✓ Background Modes")

    print()

    schemes = get_url_schemes(app)
    if schemes:
        print("URL Schemes")
        print("-----------")
        for s in schemes:
            print(f"- {s}://")
        print()

    domains = ent.get("com.apple.developer.associated-domains", [])
    if domains:
        print("Associated Domains")
        print("------------------")
        for d in domains:
            print(f"- {d}")
        print()

    print("Recommended Manual Tests")
    print("------------------------")

    if schemes:
        print("• Deep link authorization")

    if domains:
        print("• Universal Link validation")

    if ent.get("com.apple.developer.in-app-payments"):
        print("• Apple Pay flow")

    print("• Authentication & authorization")
    print("• Session management")
    print("• API authorization")

    print()

    print("Security Boundary Questions")
    print("---------------------------")
    print("• Does this cross an authentication boundary?")
    print("• Can another user trigger this action?")
    print("• Can sensitive data be accessed?")
    print("• Can you demonstrate reproducible impact?")

    return 0
