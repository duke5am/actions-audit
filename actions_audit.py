#!/usr/bin/env python3
"""actions-audit: a static supply-chain and reliability auditor for GitHub Actions.

Usage:
    python3 actions_audit.py <path> [--json] [--severity high|medium|low]
                             [--quiet] [--list-rules] [--no-color]

``<path>`` may be a single workflow file, a directory of workflow files, or a
repository root (in which case ``.github/workflows/*.yml|*.yaml`` is scanned).

Exit codes:
    0  no findings at or above the failure threshold
    1  findings at or above the failure threshold
    2  usage error, unreadable path, or unparseable YAML in an audited file
"""

from __future__ import annotations

import argparse
import os
import sys
from typing import List, Optional

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from aaudit import auditor  # noqa: E402
from aaudit import miniyaml  # noqa: E402

VERSION = "1.0.0"

# Findings at or above this severity make the process exit 1 unless --severity
# moves the bar.  "low" findings are advisory: they are always reported, but on
# their own they do not fail a build.
DEFAULT_FAIL_SEVERITY = "medium"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="actions-audit",
        description=("Static audit of GitHub Actions workflow files: mutable "
                     "action refs, pull_request_target misuse, missing "
                     "permissions, script injection, cache and deploy risks. "
                     "This tool never executes a workflow."),
        epilog=("Exit codes: 0 clean at threshold, 1 findings at/above "
                "threshold, 2 usage or parse error. Findings below the "
                "threshold are still reported; they just do not fail the run."),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("path", nargs="*",
                        help="workflow file, directory of workflows, or repository root")
    parser.add_argument("--json", action="store_true",
                        help="emit machine-readable JSON instead of text")
    parser.add_argument("--severity", choices=list(auditor.SEVERITIES),
                        default=DEFAULT_FAIL_SEVERITY,
                        help=("minimum severity that makes the exit code 1 "
                              "(default: %s). All findings are still shown."
                              % DEFAULT_FAIL_SEVERITY))
    parser.add_argument("--quiet", action="store_true",
                        help="suppress the per-file header and notes; print findings only")
    parser.add_argument("--list-rules", action="store_true",
                        help="list every rule with its severity and fix, then exit 0")
    parser.add_argument("--no-color", action="store_true",
                        help="disable ANSI colour (colour is off automatically when "
                             "stdout is not a terminal)")
    parser.add_argument("--native-yaml", action="store_true",
                        help="use the built-in YAML reader instead of PyYAML (for "
                             "environments without PyYAML, and for testing parity)")
    parser.add_argument("--version", action="version",
                        version="actions-audit %s" % VERSION)
    return parser


def print_rules(as_json: bool) -> int:
    catalogue = auditor.rule_catalogue()
    if as_json:
        import json
        print(json.dumps(catalogue, indent=2))
        return 0
    print("actions-audit %s -- %d rules\n" % (VERSION, len(catalogue)))
    for entry in catalogue:
        print("%-34s %-6s  %s" % (entry["id"], entry["severity"], entry["title"]))
        for chunk in entry["fix"].splitlines():
            print("      fix: %s" % chunk)
        print()
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.list_rules:
        return print_rules(args.json)

    if not args.path:
        parser.print_usage(sys.stderr)
        print("actions-audit: error: a path is required (file, directory, or "
              "repository root); use --list-rules to see the checks",
              file=sys.stderr)
        return 2

    try:
        findings, metas = auditor.audit_paths(
            args.path,
            prefer_native=args.native_yaml,
            base_dir=os.path.commonpath([os.path.abspath(p) for p in args.path])
            if len(args.path) > 1 else None,
        )
    except auditor.RuleError as exc:
        print("actions-audit: error: %s" % exc, file=sys.stderr)
        return 2

    if args.json:
        print(auditor.render_json(findings, metas, VERSION))
    else:
        colour = (not args.no_color) and sys.stdout.isatty()
        print(auditor.render_human(findings, metas, quiet=args.quiet, colour=colour))
        backend = metas[0]["backend"] if metas else miniyaml.backend_name()
        print("yaml backend used: %s%s"
              % (backend,
                 "" if miniyaml.pyyaml_available() else " (PyYAML not importable)"))

    threshold = auditor.SEVERITY_RANK[args.severity]
    failing = [f for f in findings if auditor.SEVERITY_RANK[f.severity] >= threshold]
    if failing:
        if not args.json:
            print("%d finding(s) at or above '%s' -- failing."
                  % (len(failing), args.severity))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
