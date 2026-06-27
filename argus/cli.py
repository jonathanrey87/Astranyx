#!/usr/bin/env python3

import argparse
from argus.plugins import analyze, evidence

VERSION = "0.1.0"

BANNER = f"""
ARGUS v{VERSION}
Mobile Application Security Research Framework

Evidence over Assumptions
Impact over Enumeration
Quality over Quantity
Methodology over Luck
"""

def build_parser():
    parser = argparse.ArgumentParser(
        prog="argus",
        description="Mobile Application Security Research Framework",
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"ARGUS v{VERSION}",
    )

    subparsers = parser.add_subparsers(dest="command")

    analyze_parser = subparsers.add_parser(
        "analyze",
        help="Analyze an app metadata file",
    )
    analyze_parser.add_argument("file", help="Path to apps.json or metadata file")
    analyze_parser.set_defaults(func=analyze.run)

    evidence_parser = subparsers.add_parser(
        "evidence",
        help="Create and manage evidence workspaces",
    )
    evidence_subparsers = evidence_parser.add_subparsers(dest="evidence_command")

    evidence_create = evidence_subparsers.add_parser(
        "create",
        help="Create a new evidence workspace",
    )
    evidence_create.add_argument("name", help="Investigation name")
    evidence_create.set_defaults(func=evidence.run)

    subparsers.add_parser("review", help="Review a potential finding")
    subparsers.add_parser("knowledge", help="Manage research knowledge")
    subparsers.add_parser("report", help="Generate report material")

    return parser

def main():
    parser = build_parser()
    args = parser.parse_args()

    if not args.command:
        print(BANNER)
        parser.print_help()
        return 0

    if hasattr(args, "func"):
        return args.func(args)

    print(f"[!] Command '{args.command}' is not implemented yet.")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
