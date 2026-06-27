from pathlib import Path
import plistlib
import zipfile
import tempfile
import shutil

def find_app_dir(path: Path) -> Path | None:
    if path.is_dir() and path.suffix == ".app":
        return path

    if path.is_dir():
        for app in path.rglob("*.app"):
            return app

    return None

def load_plist(app_dir: Path) -> dict:
    plist_path = app_dir / "Info.plist"
    if not plist_path.exists():
        raise FileNotFoundError(f"Info.plist not found: {plist_path}")

    with plist_path.open("rb") as f:
        return plistlib.load(f)

def extract_ipa(ipa_path: Path) -> Path:
    temp = Path(tempfile.mkdtemp(prefix="argus_ipa_"))

    with zipfile.ZipFile(ipa_path, "r") as z:
        z.extractall(temp)

    return temp

def get_url_schemes(info: dict) -> list[str]:
    schemes = []
    for entry in info.get("CFBundleURLTypes", []) or []:
        schemes.extend(entry.get("CFBundleURLSchemes", []) or [])
    return sorted(set(schemes))

def run(args):
    target = Path(args.file)

    if not target.exists():
        print(f"[-] Target not found: {target}")
        return 1

    temp_dir = None

    try:
        if target.suffix == ".ipa":
            temp_dir = extract_ipa(target)
            app_dir = find_app_dir(temp_dir / "Payload")
        else:
            app_dir = find_app_dir(target)

        if not app_dir:
            print("[-] Could not locate .app directory")
            return 1

        info = load_plist(app_dir)

        print("ARGUS IPA ANALYSIS")
        print("==================")
        print()
        print(f"App Directory: {app_dir}")
        print(f"Name: {info.get('CFBundleDisplayName') or info.get('CFBundleName', 'Unknown')}")
        print(f"Bundle ID: {info.get('CFBundleIdentifier', 'Unknown')}")
        print(f"Version: {info.get('CFBundleShortVersionString', 'Unknown')}")
        print(f"Build: {info.get('CFBundleVersion', 'Unknown')}")
        print(f"Minimum iOS: {info.get('MinimumOSVersion', 'Unknown')}")
        print()

        schemes = get_url_schemes(info)
        if schemes:
            print("URL Schemes")
            print("-----------")
            for s in schemes:
                print(f"- {s}://")
            print()

        associated = info.get("com.apple.developer.associated-domains")
        if associated:
            print("Associated Domains")
            print("------------------")
            for d in associated:
                print(f"- {d}")
            print()

        permissions = sorted(k for k in info.keys() if k.startswith("NS") and k.endswith("UsageDescription"))
        if permissions:
            print("Privacy Permissions")
            print("-------------------")
            for p in permissions:
                print(f"- {p}: {info.get(p)}")
            print()

        bg = info.get("UIBackgroundModes", []) or []
        if bg:
            print("Background Modes")
            print("----------------")
            for b in bg:
                print(f"- {b}")
            print()

        print("Recommended Manual Tests")
        print("------------------------")
        if schemes:
            print("- Deep link authorization testing")
        if associated:
            print("- Universal Link validation")
        if permissions:
            print("- Privacy permission behavior review")
        if bg:
            print("- Background behavior review")
        print("- API authorization testing")
        print("- Local storage review")

        return 0

    except Exception as e:
        print(f"[-] Error: {e}")
        return 1

    finally:
        if temp_dir:
            shutil.rmtree(temp_dir, ignore_errors=True)
