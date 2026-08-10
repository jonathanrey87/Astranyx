from pathlib import Path

from astranyx.services.data import load_apps


def schemes(app):
    out = []
    for item in app.get("CFBundleURLTypes", []) or []:
        out.extend(item.get("CFBundleURLSchemes", []) or [])
    return sorted(set(out))


def add(surface, name, stars, reason, tests):
    surface.append(
        {
            "name": name,
            "stars": stars,
            "reason": reason,
            "tests": tests,
        }
    )


def run(args):
    target = Path(args.file)

    if not target.exists():
        print(f"[-] File not found: {target}")
        return 1

    data = load_apps(args.file)
    app = data.get(args.bundle)

    if not app:
        print(f"[-] Bundle ID not found: {args.bundle}")
        return 1

    ent = app.get("Entitlements", {}) or {}
    name = app.get("CFBundleDisplayName") or app.get("CFBundleName") or args.bundle

    surfaces = []

    if ent.get("com.apple.developer.associated-domains"):
        add(
            surfaces,
            "Universal Links",
            "★★★★★",
            "External web links can open authenticated app flows.",
            ["AASA validation", "authorization checks", "account-bound link behavior"],
        )

    if schemes(app):
        add(
            surfaces,
            "Deep Links / URL Schemes",
            "★★★★★",
            "Custom schemes may expose app entry points.",
            [
                "login route",
                "callback route",
                "malformed parameters",
                "unauthenticated launch",
            ],
        )

    if ent.get("com.apple.developer.in-app-payments"):
        add(
            surfaces,
            "Apple Pay",
            "★★★★☆",
            "Payment flows may involve sensitive business logic.",
            ["payment authorization", "amount validation", "user confirmation"],
        )

    if ent.get("aps-environment"):
        add(
            surfaces,
            "Push Notifications",
            "★★★☆☆",
            "Notifications may trigger app behavior or sensitive views.",
            ["notification deep links", "lock-screen behavior", "account context"],
        )

    if app.get("UIBackgroundModes"):
        add(
            surfaces,
            "Background Modes",
            "★★★☆☆",
            "Background execution can affect privacy and session behavior.",
            ["background location", "remote notification handling", "state changes"],
        )

    print("ASTRANYX THREAT MODEL")
    print("==================")
    print()
    print("Application")
    print("-----------")
    print(f"Name: {name}")
    print(f"Bundle ID: {args.bundle}")
    print()

    print("Primary Attack Surfaces")
    print("-----------------------")
    if not surfaces:
        print("No high-priority mobile surfaces identified.")
    else:
        for s in surfaces:
            print(f"{s['stars']} {s['name']}")
            print(f"  Why: {s['reason']}")
    print()

    print("Likely Trust Boundaries")
    print("-----------------------")
    boundaries = [
        "External browser → Mobile app",
        "Mobile app → Backend API",
        "Anonymous user → Authenticated session",
        "User account → User data",
    ]
    if ent.get("aps-environment"):
        boundaries.append("Push service → App behavior")
    if ent.get("com.apple.developer.in-app-payments"):
        boundaries.append("Payment authorization → Backend validation")

    for b in boundaries:
        print(f"- {b}")
    print()

    print("Suggested Investigation Order")
    print("-----------------------------")
    order = []
    for s in surfaces:
        order.extend(s["tests"])

    for i, test in enumerate(dict.fromkeys(order), start=1):
        print(f"{i}. {test}")

    print()
    print("Potential Bug Classes")
    print("---------------------")
    print("- Authentication bypass")
    print("- Authorization bypass")
    print("- Business logic flaw")
    print("- Sensitive data exposure")
    print("- Deep link handling issue")

    return 0
