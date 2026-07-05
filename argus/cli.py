import argparse
from argus.modules import js


def run_js(args):
    js.analyze(args.path, args.output)


def main():
    parser = argparse.ArgumentParser(prog="argus")

    subparsers = parser.add_subparsers(dest="command")

    js_parser = subparsers.add_parser(
        "js",
        help="JavaScript analysis"
    )

    js_sub = js_parser.add_subparsers(dest="js_command")

    analyze = js_sub.add_parser(
        "analyze",
        help="Analyze JavaScript bundles"
    )

    analyze.add_argument(
        "path",
        help="Directory containing JS files"
    )

    analyze.add_argument(
        "-o",
        "--output",
        help="Write JSON report"
    )

    analyze.set_defaults(func=run_js)

    args = parser.parse_args()

    if hasattr(args, "func"):
        args.func(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
