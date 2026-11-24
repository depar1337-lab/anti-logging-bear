# Anti-Logging Bear by Priest

from __future__ import annotations

import argparse
import os
import sys

from . import APP_NAME, __version__


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="antiloggingbear",
        description=f"{APP_NAME} - checks downloads for keyloggers and malware before you unzip them.",
    )
    parser.add_argument("paths", nargs="*", help="files, archives or folders to check")
    parser.add_argument("--gui", action="store_true", help="open the window (and scan any given paths)")
    parser.add_argument("--background", action="store_true", help="start hidden and watch for downloads")
    parser.add_argument("--json", action="store_true", help="print a JSON report")
    parser.add_argument("--html", metavar="FILE", help="write an HTML report to FILE")
    parser.add_argument("-v", "--verbose", action="store_true", help="show every finding with details")
    parser.add_argument("--strict", action="store_true", help="treat medium findings as suspicious")
    parser.add_argument("--no-av", action="store_true", help="skip the system antivirus check")
    parser.add_argument("--no-yara", action="store_true", help="skip YARA rules")
    parser.add_argument("--vt-key", metavar="KEY", help="VirusTotal API key (hash lookups only)")
    parser.add_argument("--mb-key", metavar="KEY", help="MalwareBazaar Auth-Key (hash lookups only)")
    parser.add_argument("--version", action="version", version=f"{APP_NAME} {__version__}")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    windowed = sys.stdout is None
    if args.gui or args.background or not args.paths or windowed:
        from .app import run_app
        return run_app(args.paths, background=args.background)
    return _run_cli(args)


def _run_cli(args: argparse.Namespace) -> int:
    from . import report as fmt
    from . import settings as config
    from .engine import scan_path

    options = config.load().scan_options()
    options.strict = options.strict or args.strict
    options.use_antivirus = options.use_antivirus and not args.no_av
    options.use_yara = options.use_yara and not args.no_yara
    if args.vt_key:
        options.vt_api_key = args.vt_key
    if args.mb_key:
        options.mb_api_key = args.mb_key

    worst = 0
    for path in args.paths:
        if not (os.path.isfile(path) or os.path.isdir(path)):
            print(f"{path}: not a file", file=sys.stderr)
            worst = max(worst, 3)
            continue
        result = scan_path(path, options)
        if args.json:
            print(fmt.to_json(result))
        else:
            print(fmt.to_text(result, verbose=args.verbose))
            print()
        if args.html:
            with open(args.html, "w", encoding="utf-8") as fh:
                fh.write(fmt.to_html(result))
        worst = max(worst, result.verdict.exit_code)
    return worst


if __name__ == "__main__":
    sys.exit(main())
