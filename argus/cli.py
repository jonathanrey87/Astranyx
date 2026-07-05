import argparse
from argus.modules import js


def main():
    parser = argparse.ArgumentParser(prog="argus")
    subparsers = parser.add_subparsers(dest="command")

    js_parser = subparsers.add_parser("js", help="Analyze JavaScript bundles")
    js_parser.add_argument("path", help="Directory containing JS files")
    js_parser.set_defaults(func=run_js)

    args = parser.parse_args()

    if not hasattr(args, "func"):
        parser.print_help()
        return

    args.func(args)


def run_js(args):
    js.analyze(args.path)


if __name__ == "__main__":
    main()
