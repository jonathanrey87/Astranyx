import json
import subprocess
from pathlib import Path

OUT = Path.home() / "apps.json"
RAW = Path.home() / "apps_raw.txt"


def run(args):
    print("ARGUS EXTRACTION")
    print("================")
    print()

    cmd = ["pymobiledevice3", "apps", "list"]

    print("[*] Running:", " ".join(cmd))
    result = subprocess.run(cmd, capture_output=True, text=True, check=False)

    RAW.write_text(result.stdout)

    if result.returncode != 0:
        print("[-] pymobiledevice3 failed")
        print(result.stderr)
        return 1

    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        print("[!] Output was not JSON.")
        print(f"[+] Raw output saved to: {RAW}")
        print("[!] apps.json was NOT overwritten.")
        return 1

    if not isinstance(data, dict):
        print("[-] JSON output was not the expected app dictionary.")
        return 1

    OUT.write_text(json.dumps(data, indent=2, sort_keys=True))
    print(f"[+] Saved valid app database: {OUT}")
    print(f"[+] Apps collected: {len(data)}")
    return 0
