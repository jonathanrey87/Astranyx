#!/usr/bin/env python3

import sys

VERSION = "0.1.0"

BANNER = f"""
╔══════════════════════════════════════════════╗
║                 ARGUS v{VERSION}                 ║
║   Mobile Application Security Framework     ║
╚══════════════════════════════════════════════╝

Evidence over Assumptions
Impact over Enumeration
Quality over Quantity
Methodology over Luck
"""


def show_help():
    print("""
Available Commands

  analyze <file>
  focus <bundle_id>
  review
  evidence
  knowledge
  report
  version
  help
""")


def analyze(args):
    if not args:
        print("Usage: argus analyze <file>")
        return

    print("[+] Analyze engine starting...")
    print(f"[+] Target: {args[0]}")
    print()
    print("(Feature not implemented yet.)")


def main():

    if len(sys.argv) == 1:
        print(BANNER)
        return

    command = sys.argv[1].lower()

    if command == "help":
        show_help()

    elif command == "version":
        print(f"ARGUS v{VERSION}")

    elif command == "analyze":
        analyze(sys.argv[2:])

    else:
        print(f"Unknown command: {command}")
        print("Run 'argus help'")


if __name__ == "__main__":
    main()
