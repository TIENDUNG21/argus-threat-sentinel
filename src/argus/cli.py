"""Command-line interface.

Exit codes: 0 success, 1 ``--fail-on`` threshold reached, 2 usage or input
errors (bad rule file, unreadable input, unknown format).
"""

from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Sequence
from pathlib import Path

from argus import __version__
from argus.alerts import Severity
from argus.events import SSH, WEB
from argus.ingest.reader import FORMATS, detect_format
from argus.ml.detector import AnomalyConfig
from argus.pipeline import ScanOptions, load_rule_set, scan
from argus.rules.errors import RuleError
from argus.rules.loader import load_rules

EXIT_OK, EXIT_FINDINGS, EXIT_ERROR = 0, 1, 2


def _use_color(choice: str, stream: object) -> bool:
    if choice == "always":
        return True
    if choice == "never" or os.environ.get("NO_COLOR"):
        return False
    isatty = getattr(stream, "isatty", None)
    return bool(isatty and isatty())


def _sources(text: str) -> tuple[str, ...]:
    sources = tuple(part.strip() for part in text.split(",") if part.strip())
    if not sources or set(sources) - {WEB, SSH}:
        raise argparse.ArgumentTypeError("use web, ssh or web,ssh")
    return sources


def _add_input_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--format",
        choices=("auto", *FORMATS),
        default="auto",
        help="log format (default: detect per file)",
    )
    parser.add_argument(
        "--year", type=int, help="year for syslog timestamps without one (default: current)"
    )
    parser.add_argument(
        "--rules",
        type=Path,
        action="append",
        default=[],
        metavar="FILE",
        help="extra TOML rule file (repeatable)",
    )
    parser.add_argument("--no-builtin", action="store_true", help="skip the built-in rules")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="argus",
        description="Intrusion detection for web and SSH logs: ATT&CK-mapped rules plus "
        "an Isolation Forest over per-actor behaviour.",
    )
    parser.add_argument("--version", action="version", version=f"argus {__version__}")
    commands = parser.add_subparsers(dest="command", metavar="COMMAND")

    scan_cmd = commands.add_parser("scan", help="analyse log files and report incidents")
    scan_cmd.add_argument("paths", type=Path, nargs="+", metavar="PATH")
    _add_input_options(scan_cmd)
    scan_cmd.add_argument("--no-ml", action="store_true", help="skip the anomaly model")
    scan_cmd.add_argument(
        "--ml-sources",
        type=_sources,
        default=(WEB,),
        metavar="LIST",
        help="sources to model: web (default), ssh or web,ssh",
    )
    scan_cmd.add_argument(
        "--ml-threshold",
        type=float,
        default=AnomalyConfig().threshold,
        metavar="SCORE",
        help="anomaly score that flags an actor (default: %(default)s)",
    )
    scan_cmd.add_argument("--seed", type=int, default=0, help="anomaly model seed")
    scan_cmd.add_argument("--html", type=Path, metavar="FILE", help="write the HTML report")
    scan_cmd.add_argument("--json", type=Path, metavar="FILE", help="write the JSON report")
    scan_cmd.add_argument("--label", help="banner text for the HTML report")
    scan_cmd.add_argument("--top", type=int, default=15, help="incidents listed in the summary")
    scan_cmd.add_argument(
        "--fail-on",
        choices=[level.label for level in Severity],
        metavar="LEVEL",
        help="exit with 1 if any incident reaches LEVEL (low, medium, high, critical)",
    )
    scan_cmd.add_argument("--quiet", action="store_true", help="no terminal summary")
    scan_cmd.add_argument("--color", choices=("auto", "always", "never"), default="auto")

    tail_cmd = commands.add_parser("tail", help="follow a growing log and print alerts live")
    tail_cmd.add_argument("path", type=Path, metavar="PATH")
    _add_input_options(tail_cmd)
    tail_cmd.add_argument("--from-start", action="store_true", help="read existing lines first")
    tail_cmd.add_argument("--poll", type=float, default=0.5, metavar="SECONDS")
    tail_cmd.add_argument("--color", choices=("auto", "always", "never"), default="auto")

    sim_cmd = commands.add_parser("simulate", help="write labelled synthetic logs")
    sim_cmd.add_argument("--out", type=Path, required=True, metavar="DIR")
    sim_cmd.add_argument("--seed", type=int, default=7)
    sim_cmd.add_argument("--hours", type=int, default=48)
    sim_cmd.add_argument("--visitors", type=int, default=300, help="visitors per day")

    rules_cmd = commands.add_parser("rules", help="list or validate detection rules")
    rules_sub = rules_cmd.add_subparsers(dest="rules_command", metavar="ACTION", required=True)
    list_cmd = rules_sub.add_parser("list", help="print the loaded rules")
    list_cmd.add_argument("--rules", type=Path, action="append", default=[], metavar="FILE")
    list_cmd.add_argument("--no-builtin", action="store_true")
    check_cmd = rules_sub.add_parser("check", help="validate rule files")
    check_cmd.add_argument("files", type=Path, nargs="+", metavar="FILE")
    return parser


def _cmd_scan(args: argparse.Namespace) -> int:
    from argus.report.html import write_html
    from argus.report.json_report import write_json
    from argus.report.terminal import render_summary

    options = ScanOptions(
        fmt=args.format,
        year=args.year,
        rule_paths=tuple(args.rules),
        builtin=not args.no_builtin,
        ml=not args.no_ml,
        anomaly=AnomalyConfig(threshold=args.ml_threshold, seed=args.seed, sources=args.ml_sources),
    )
    try:
        result = scan(args.paths, options)
    except RuleError as exc:
        print(f"argus: {exc}", file=sys.stderr)
        return EXIT_ERROR
    unreadable = [i for i in result.inputs if i.errors and i.lines == 0]
    for summary in unreadable:
        for error in summary.errors:
            print(f"argus: {error}", file=sys.stderr)
    if len(unreadable) == len(result.inputs):
        return EXIT_ERROR
    if args.html:
        write_html(result, args.html, label=args.label)
    if args.json:
        write_json(result, args.json, label=args.label)
    if not args.quiet:
        sys.stdout.write(
            render_summary(result, color=_use_color(args.color, sys.stdout), top=args.top)
        )
    if args.fail_on:
        floor = Severity.parse(args.fail_on)
        if any(incident.level >= floor for incident in result.incidents):
            return EXIT_FINDINGS
    return EXIT_OK


def _cmd_tail(args: argparse.Namespace) -> int:
    from argus.live import follow

    fmt = args.format
    if fmt == "auto":
        detected = None
        if args.path.is_file() and args.path.stat().st_size > 0:
            detected = detect_format(args.path, year=args.year)
        if detected is None:
            print(
                f"argus: cannot detect the format of {args.path}; pass --format",
                file=sys.stderr,
            )
            return EXIT_ERROR
        fmt = detected
    try:
        rules = load_rule_set(
            ScanOptions(rule_paths=tuple(args.rules), builtin=not args.no_builtin)
        )
    except RuleError as exc:
        print(f"argus: {exc}", file=sys.stderr)
        return EXIT_ERROR
    print(
        f"argus: following {args.path} ({fmt}, {len(rules)} rules); Ctrl-C to stop", file=sys.stderr
    )
    try:
        follow(
            args.path,
            fmt,
            rules,
            sys.stdout,
            year=args.year,
            from_start=args.from_start,
            poll=args.poll,
            color=_use_color(args.color, sys.stdout),
        )
    except KeyboardInterrupt:
        print("argus: stopped", file=sys.stderr)
    return EXIT_OK


def _cmd_simulate(args: argparse.Namespace) -> int:
    from argus.simulate import simulate, write_simulation

    try:
        simulation = simulate(args.seed, hours=args.hours, visitors_per_day=args.visitors)
    except ValueError as exc:
        print(f"argus: {exc}", file=sys.stderr)
        return EXIT_ERROR
    written = write_simulation(simulation, args.out)
    labels = simulation.labels
    malicious = sum(label.malicious for label in labels.actors.values())
    print(
        f"wrote {len(simulation.access_lines):,} access lines, {len(simulation.auth_lines):,} "
        f"auth lines ({sum(labels.malformed.values())} deliberately malformed) and labels for "
        f"{len(labels.actors):,} actors ({malicious:,} malicious) to {args.out}"
    )
    for path in written.values():
        print(f"  {path}")
    return EXIT_OK


def _cmd_rules(args: argparse.Namespace) -> int:
    if args.rules_command == "check":
        status = EXIT_OK
        for path in args.files:
            try:
                loaded = load_rules([path])
            except RuleError as exc:
                print(f"argus: {exc}", file=sys.stderr)
                status = EXIT_ERROR
            else:
                print(f"{path}: {len(loaded)} rules OK")
        return status
    try:
        rules = load_rule_set(
            ScanOptions(rule_paths=tuple(args.rules), builtin=not args.no_builtin)
        )
    except RuleError as exc:
        print(f"argus: {exc}", file=sys.stderr)
        return EXIT_ERROR
    width = max((len(rule.id) for rule in rules), default=10)
    print(f"{'RULE':<{width}}  {'SEVERITY':<8}  {'TECHNIQUE':<10}  TITLE")
    for rule in rules:
        print(f"{rule.id:<{width}}  {rule.severity.label:<8}  {rule.technique:<10}  {rule.title}")
    return EXIT_OK


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command is None:
        parser.print_help(sys.stderr)
        return EXIT_ERROR
    handlers = {
        "scan": _cmd_scan,
        "tail": _cmd_tail,
        "simulate": _cmd_simulate,
        "rules": _cmd_rules,
    }
    return handlers[args.command](args)
