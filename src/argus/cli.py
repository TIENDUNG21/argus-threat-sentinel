"""Command-line interface."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence

from argus import __version__


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="argus",
        description="Intrusion detection that reads your logs. Rules plus unsupervised ML.",
    )
    parser.add_argument("--version", action="version", version=f"argus {__version__}")
    parser.add_subparsers(dest="command", metavar="COMMAND")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command is None:
        parser.print_help(sys.stderr)
        return 2
    return 0
