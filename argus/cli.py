import argparse

from argus.modules import js
from argus.commands import report as report_command
from argus.wordpress import scanner


def run_js(args):
    js.analyze(args.path, args.output)


def run_report(args):
    report_command.run(args.report_json)


def run_wordpress(args):
    scanner.run(args.path)


def main():
    parser = argparse.ArgumentParser(prog="argus")
    subparsers = parser.add_subparsers(dest="command")

    js_parser = subparsers.add_parser("js", help="JavaScript analysis")
    js_sub = js_parser.add_subparsers(dest="js_command")

    analyze = js_sub.add_parser("analyze", help="Analyze JavaScript bundles")
    analyze.add_argument("path", help="Directory containing JS files")
    analyze.add_argument("-o", "--output", help="Write JSON report")
    analyze.set_defaults(func=run_js)

    report_parser = subparsers.add_parser(
        "report",
        help="Generate HTML and Markdown reports",
    )
    report_parser.add_argument("report_json", help="Path to analysis/report.json")
    report_parser.set_defaults(func=run_report)

    wordpress_parser = subparsers.add_parser(
        "wordpress",
        help="Audit a WordPress plugin",
    )
    wordpress_parser.add_argument("path", help="Plugin directory")
    wordpress_parser.set_defaults(func=run_wordpress)

    args = parser.parse_args()

    if hasattr(args, "func"):
        args.func(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
