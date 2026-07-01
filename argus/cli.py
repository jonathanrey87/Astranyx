#!/usr/bin/env python3

import argparse
from argus.plugins import analyze, evidence, review, ipa, focus, threat, report, playbook, investigate, extract

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

    review_parser = subparsers.add_parser(
        "review",
        help="Review an evidence workspace",
    )
    review_parser.add_argument("path", help="Path to evidence workspace")
    review_parser.set_defaults(func=review.run)
    subparsers.add_parser("knowledge", help="Manage research knowledge")

    ipa_parser = subparsers.add_parser(
        "ipa",
        help="Analyze an IPA file or extracted .app directory",
    )
    ipa_parser.add_argument("file", help="Path to .ipa or .app directory")
    ipa_parser.set_defaults(func=ipa.run)
    focus_parser = subparsers.add_parser(
   	 "focus",
    	 help="Focus on a single application",
    
    )

    focus_parser.add_argument(
    	"bundle",
    	help="Bundle ID",
    )

    focus_parser.add_argument(
    	"file",
    	help="Path to apps.json",
    )

    focus_parser.set_defaults(func=focus.run)
    

    threat_parser = subparsers.add_parser(
        "threat",
        help="Generate a threat model for one application",
    )
    threat_parser.add_argument("bundle", help="Bundle ID")
    threat_parser.add_argument("file", help="Path to apps.json")
    threat_parser.set_defaults(func=threat.run)


    playbook_parser = subparsers.add_parser(
        "playbook",
        help="Show a testing playbook",
    )
    playbook_parser.add_argument("name", help="Playbook name")
    playbook_parser.set_defaults(func=playbook.run)

    report_parser = subparsers.add_parser(
	"report",
	help="Generate a report template",
    )

    report_parser.add_argument(
	"path",
	help="Evidence workspace",
    )

    report_parser.set_defaults(func=report.run) 

    investigate_parser = subparsers.add_parser(
	"investigate",
	help="Start a guided investigation",
    )
    investigate_parser.add_argument("bundle_id")
    investigate_parser.add_argument("metadata")
    investigate_parser.set_defaults(func=investigate.run)

    extract_parser = subparsers.add_parser(
	"extract",
	help="Extract application metadata from connected device",
    )
    extract_parser.set_defaults(func=extract.run)

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
