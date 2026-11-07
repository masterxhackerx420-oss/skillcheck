"""Small terminal/JSON interface."""

import argparse
import json
import sys

from . import __version__
from .scanner import RULES, safe, scan


class Parser(argparse.ArgumentParser):
    def error(self, message):
        if self.json_mode:
            print(json.dumps({"errors": [{"file": "", "error": message}], "exit_code": 2},
                             ensure_ascii=True))
            self.exit(2)
        super().error(safe(message, 500))


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    parser = Parser(description="Offline heuristic skill linter; never executes scanned text.")
    parser.json_mode = "--json" in argv
    parser.add_argument("path", nargs="?", help="skill directory or UTF-8 text file")
    parser.add_argument("--json", action="store_true", help="emit a deterministic JSON report")
    parser.add_argument("--list-rules", action="store_true", help="describe the four heuristic rules")
    parser.add_argument("--version", action="version", version=f"skillcheck {__version__}")
    args = parser.parse_args(argv)
    if args.list_rules:
        rules = [{"rule_id": key, "severity": value[0], "title": value[1], "rationale": value[2]}
                 for key, value in RULES.items()]
        print(json.dumps(rules, ensure_ascii=True, indent=2) if args.json else "\n".join(
            f"{r['rule_id']} [{r['severity']}] {r['title']}: {r['rationale']}" for r in rules))
        return 0
    if args.path is None:
        if args.json:
            print(json.dumps({"errors": [{"file": "", "error": "PATH is required"}], "exit_code": 2}))
            return 2
        parser.error("PATH is required")
    report = scan(args.path)
    if args.json:
        print(json.dumps(report.as_dict(), ensure_ascii=True, sort_keys=True, indent=2))
    else:
        for finding in report.findings:
            print(f"{safe(finding['file'], 500)}:{finding['line']}: {finding['rule_id']} "
                  f"[{finding['severity']}] {finding['title']}")
            print(f"  {finding['rationale']}\n  | {finding['context']}")
        for item in report.skipped:
            print(f"SKIP {safe(item['file'], 500)}: {item['reason']}")
        for item in report.errors:
            print(f"ERROR {safe(item['file'], 500)}: {safe(item['error'], 500)}")
        print(f"scanned {report.scanned_files} file(s); {len(report.findings)} finding(s); "
              f"skipped {len(report.skipped)} entry/entries; {len(report.errors)} error(s)")
        if report.errors:
            print("scan incomplete: errors occurred; do not treat this as clean.")
        elif not report.findings:
            print("no findings in scanned files; skipped content is not assessed. Not a safety certificate.")
    return report.exit_code
