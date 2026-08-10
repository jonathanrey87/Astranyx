def recommend(app):
    recs = []

    schemes = []
    for item in app.get("CFBundleURLTypes", []) or []:
        schemes.extend(item.get("CFBundleURLSchemes", []) or [])

    entitlements = app.get("Entitlements", {}) or {}

    if schemes:
        recs.append("deeplink")

    if entitlements.get("com.apple.developer.associated-domains"):
        recs.append("universal_links")

    if entitlements.get("com.apple.developer.in-app-payments"):
        recs.append("apple_pay")

    if entitlements.get("aps-environment"):
        recs.append("push_notifications")

    return sorted(set(recs))
