import argparse

from astranyx import __version__
from astranyx.commands import report as report_command
from astranyx.investigation import orchestrator
from astranyx.investigation import run as investigation_command
from astranyx.modules import js
from astranyx.tracing import configure_tracing
from astranyx.wordpress import scanner


def run_js(args):
    """Run JavaScript analysis."""
    js.analyze(
        path=args.path,
        output=args.output,
        investigation=args.investigation,
        recursive=args.recursive,
    )


def run_report(args):
    """Generate reports from an Astranyx JSON report."""
    report_command.run(args.report_json)


def run_wordpress(args):
    """Run the WordPress plugin scanner."""
    scanner.run(args.path)


def run_investigation(args):
    """Create a workspace and optionally run an investigation pipeline."""
    positional_target = getattr(args, "path", None)
    option_target = getattr(args, "target", None)

    if (
        positional_target
        and option_target
        and str(positional_target) != str(option_target)
    ):
        raise SystemExit(
            "[!] Supply the target either positionally or with --target, not both"
        )

    target = positional_target or option_target
    args.target = target

    if target is None:
        return investigation_command.run(args)

    try:
        return orchestrator.run(
            target,
            analyst=args.analyst,
            profile=args.profile,
            recursive=args.recursive,
            trace_enabled=args.trace_enabled,
            workspace_root=args.workspace_root,
        )
    except (FileNotFoundError, NotADirectoryError, ValueError) as exc:
        raise SystemExit(f"[!] {exc}") from exc


def main():
    """Astranyx command-line entry point."""
    tracer = configure_tracing()

    parser = argparse.ArgumentParser(
        prog="astranyx",
        description=("Astranyx Threat Intelligence Automation Framework"),
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )

    subparsers = parser.add_subparsers(dest="command")

    # JavaScript commands
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
            "Path to an Astranyx investigation workspace, "
            "for example investigations/INV-20260721-171856"
        ),
    )

    analyze_parser.add_argument(
        "--recursive",
        action="store_true",
        help="Discover JavaScript files in nested directories",
    )

    analyze_parser.set_defaults(func=run_js)

    # Report command
    report_parser = subparsers.add_parser(
        "report",
        help="Generate HTML and Markdown reports",
    )

    report_parser.add_argument(
        "report_json",
        help="Path to an Astranyx JSON report",
    )

    report_parser.set_defaults(func=run_report)

    # WordPress command
    wordpress_parser = subparsers.add_parser(
        "wordpress",
        help="Audit a WordPress plugin",
    )

    wordpress_parser.add_argument(
        "path",
        help="Path to the WordPress plugin directory",
    )

    wordpress_parser.set_defaults(func=run_wordpress)

    # Investigation command
    investigation_parser = subparsers.add_parser(
        "investigate",
        help="Create or run an investigation",
        description=(
            "Create an investigation workspace and, when a local target is "
            "supplied, run the selected analysis profile"
        ),
    )

    investigation_parser.add_argument(
        "path",
        nargs="?",
        help="Optional local, authorized target to analyze",
    )

    investigation_parser.add_argument(
        "--analyst",
        default="Jonathan Mendiola",
        help="Name of the analyst creating the investigation",
    )

    investigation_parser.add_argument(
        "--target",
        help="Compatibility alias for the positional target path",
    )

    investigation_parser.add_argument(
        "--profile",
        choices=orchestrator.SUPPORTED_PROFILES,
        default="auto",
        help="Analysis profile (default: auto)",
    )

    investigation_parser.add_argument(
        "--recursive",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Discover supported source files recursively (default: enabled)",
    )

    investigation_parser.add_argument(
        "--workspace-root",
        default="investigations",
        help="Parent directory for investigation workspaces",
    )

    investigation_parser.set_defaults(
        func=run_investigation,
    )

    args = parser.parse_args()
    args.trace_enabled = tracer is not None

    if not hasattr(args, "func"):
        parser.print_help()
        return

    # Run normally when tracing credentials are unavailable.
    if tracer is None:
        args.func(args)
        return

    span_name = f"astranyx.cli.{args.command}"

    with tracer.start_as_current_span(span_name) as span:
        span.set_attribute(
            "astranyx.command",
            args.command,
        )

        if getattr(args, "js_command", None):
            span.set_attribute(
                "astranyx.subcommand",
                args.js_command,
            )

        if getattr(args, "path", None):
            span.set_attribute(
                "astranyx.input.path",
                str(args.path),
            )

        if getattr(args, "investigation", None):
            span.set_attribute(
                "astranyx.investigation.path",
                str(args.investigation),
            )

        if getattr(args, "recursive", False):
            span.set_attribute(
                "astranyx.javascript.recursive",
                True,
            )

        if getattr(args, "target", None):
            span.set_attribute(
                "astranyx.target",
                str(args.target),
            )

        if getattr(args, "analyst", None):
            span.set_attribute(
                "astranyx.analyst",
                str(args.analyst),
            )

        if getattr(args, "profile", None):
            span.set_attribute(
                "astranyx.investigation.profile",
                str(args.profile),
            )

        args.func(args)


if __name__ == "__main__":
    main()
