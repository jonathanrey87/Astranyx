from pathlib import Path
import json

SENSITIVE_PERMISSIONS = [
    "NSCameraUsageDescription",
    "NSMicrophoneUsageDescription",
    "NSLocationWhenInUseUsageDescription",
    "NSLocationAlwaysAndWhenInUseUsageDescription",
    "NSPhotoLibraryUsageDescription",
    "NSContactsUsageDescription",
    "NSUserTrackingUsageDescription",
]

def get_schemes(app):
    schemes = []
    for item in app.get("CFBundleURLTypes", []) or []:
        schemes.extend(item.get("CFBundleURLSchemes", []) or [])
    return sorted(set(schemes))

def score_app(app):
    ent = app.get("Entitlements", {}) or {}
    score = 0
    reasons = []

    if get_schemes(app):
        score += 3
        reasons.append("URL schemes")

    if ent.get("com.apple.developer.associated-domains"):
        score += 4
        reasons.append("Universal Links")

    if ent.get("com.apple.developer.in-app-payments"):
        score += 4
        reasons.append("Apple Pay")

    if app.get("UIBackgroundModes"):
        score += 2
        reasons.append("Background modes")

    if ent.get("aps-environment"):
        score += 1
        reasons.append("Push notifications")

    for key in SENSITIVE_PERMISSIONS:
        if key in app:
            score += 1
            reasons.append(key.replace("NS", "").replace("UsageDescription", ""))

    return score, sorted(set(reasons))

def stars(score):
    if score >= 12:
        return "★★★★★"
    if score >= 8:
        return "★★★★☆"
    if score >= 5:
        return "★★★☆☆"
    if score >= 3:
        return "★★☆☆☆"
    return "★☆☆☆☆"

def run(args):
    target = Path(args.file)

    print("[+] Analyze plugin starting...")
    print(f"[+] Target: {target}")

    if not target.exists():
        print(f"[-] File not found: {target}")
        return 1

    try:
        data = json.loads(target.read_text())
    except Exception as e:
        print(f"[-] Could not parse JSON: {e}")
        return 1

    rows = []
    total_schemes = 0
    total_universal = 0

    for bundle_id, app in data.items():
        score, reasons = score_app(app)
        schemes = get_schemes(app)
        ent = app.get("Entitlements", {}) or {}
        domains = ent.get("com.apple.developer.associated-domains", []) or []

        total_schemes += len(schemes)
        total_universal += len([d for d in domains if str(d).startswith("applinks:")])

        if score >= 5:
            rows.append({
                "name": app.get("CFBundleDisplayName") or app.get("CFBundleName") or bundle_id,
                "bundle": bundle_id,
                "score": score,
                "stars": stars(score),
                "reasons": reasons,
            })

    rows.sort(key=lambda r: r["score"], reverse=True)

    print()
    print("ARGUS MOBILE INTELLIGENCE")
    print("=========================")
    print(f"Applications analyzed: {len(data)}")
    print(f"High-interest apps: {len(rows)}")
    print(f"URL schemes found: {total_schemes}")
    print(f"Universal Link entries: {total_universal}")
    print()

    print("Top Priority")
    print("------------")
    for row in rows[:15]:
        print(f"{row['stars']} {row['name']} ({row['bundle']})")
        print(f"  Score: {row['score']}")
        print(f"  Why: {', '.join(row['reasons'])}")
        print()

    print("Next Steps")
    print("----------")
    print("- Create an evidence workspace for one target")
    print("- Run focused analysis on that bundle ID")
    print("- Identify a security boundary before manual testing")
    print("- Do not submit without reproducible impact")

    return 0
