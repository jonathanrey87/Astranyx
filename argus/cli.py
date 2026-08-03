import argparse

from argus.commands import report as report_command
from argus.investigation import run as investigation_command
from argus.modules import js
from argus.tracing import configure_tracing
from argus.wordpress import scanner


def run_js(args):
    """Run JavaScript analysis."""
    js.analyze(
        path=args.path,
        output=args.output,
        investigation=args.investigation,
    )


def run_report(args):
    """Generate reports from an Argus JSON report."""
    report_command.run(args.report_json)


def run_wordpress(args):
    """Run the WordPress plugin scanner."""
    scanner.run(args.path)


def run_investigation(args):
    """Create a new investigation workspace."""
    investigation_command.run(args)


def main():
    """Argus command-line entry point."""
    tracer = configure_tracing()

    parser = argparse.ArgumentParser(
        prog="argus",
        description="Argus Threat Intelligence Automation Framework",
    )

    subparsers = parser.add_subparsers(dest="command")

    # ---------------------------------------------------------
    # JavaScript commands
    # ---------------------------------------------------------
    js_parser = subparsers.add_parser(
        "js",
        help="JavaScript analysis",
    )

    js_subparsers = js_parser.add_subparsers(
        dest="js_command",
    )

    analyze_parser = js_subparsers.add_parser(
        "analyze",
        help="Analyze JavaScript bundles",
    )

    analyze_parser.add_argument(
        "path",
        help="Directory containing JavaScript files",
    )

    analyze_parser.add_argument(
        "-o",
        "--output",
        help="Optional path for the JSON report",
    )

    analyze_parser.add_argument(
        "--investigation",
        help=(
            "Path to an Argus investigation workspace, "
            "for example investigations/INV-20260721-171856"
        ),
    )

    analyze_parser.set_defaults(func=run_js)

    # ---------------------------------------------------------
    # Report command
    # ---------------------------------------------------------
    report_parser = subparsers.add_parser(
        "report",
        help="Generate HTML and Markdown reports",
    )

    report_parser.add_argument(
        "report_json",
        help="Path to an Argus JSON report",
    )

    report_parser.set_defaults(func=run_report)

    # ---------------------------------------------------------
    # WordPress command
    # ---------------------------------------------------------
    wordpress_parser = subparsers.add_parser(
        "wordpress",
        help="Audit a WordPress plugin",
    )

    wordpress_parser.add_argument(
        "path",
        help="Path to the WordPress plugin directory",
    )

    wordpress_parser.set_defaults(func=run_wordpress)

    # ---------------------------------------------------------
    # Investigation command
    # ---------------------------------------------------------
    investigation_parser = subparsers.add_parser(
        "investigate",
        help="Create a new investigation workspace",
    )

    investigation_parser.set_defaults(
        func=run_investigation,
    )

    args = parser.parse_args()

    if not hasattr(args, "func"):
        parser.print_help()
        return

    # Run normally when tracing credentials are unavailable.
    if tracer is None:
        args.func(args)
        return

    span_name = f"argus.cli.{args.command}"

    with tracer.start_as_current_span(span_name) as span:
        span.set_attribute(
            "argus.command",
            args.command,
        )

        if getattr(args, "js_command", None):
            span.set_attribute(
                "argus.subcommand",
                args.js_command,
            )

        if getattr(args, "path", None):
            span.set_attribute(
                "argus.input.path",
                str(args.path),
            )

        if getattr(args, "investigation", None):
            span.set_attribute(
                "argus.investigation.path",
                str(args.investigation),
            )

        args.func(args)


if __name__ == "__main__":
    main()
