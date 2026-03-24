#!/usr/bin/env python3
import argparse
import json
from collections import Counter
from pathlib import Path


def load_report(path: Path) -> dict:
    with path.open(encoding="utf-8") as f:
        return json.load(f)


def list_findings(results: list[dict], limit: int | None = None) -> None:
    for i, item in enumerate(results):
        if limit is not None and i >= limit:
            break
        severity = item.get("extra", {}).get("severity", "UNKNOWN")
        check_id = item.get("check_id", "unknown-rule")
        file_path = item.get("path", "unknown-file")
        line = item.get("start", {}).get("line", "?")
        message = (item.get("extra", {}).get("message", "") or "").replace("\n", " ")
        print(f"[{severity}] {check_id}")
        print(f"  -> {file_path}:{line}")
        print(f"  -> {message}")
        print()


def print_summary(results: list[dict]) -> None:
    print(f"Total findings: {len(results)}")
    print()

    by_rule = Counter(item.get("check_id", "unknown-rule") for item in results)
    by_severity = Counter(
        item.get("extra", {}).get("severity", "UNKNOWN") for item in results
    )

    print("Findings by severity:")
    for severity, count in by_severity.most_common():
        print(f"  {severity}: {count}")
    print()

    print("Top rules:")
    for rule, count in by_rule.most_common(10):
        print(f"  {count:>3}  {rule}")
    print()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Analyze Semgrep JSON report and print readable summary."
    )
    parser.add_argument(
        "--report",
        default="reports/semgrep-owasp-top-ten.json",
        help="Path to Semgrep JSON report",
    )
    parser.add_argument(
        "--after", default="", help="Optional second report for before/after comparison"
    )
    parser.add_argument("--list", action="store_true", help="Print individual findings")
    parser.add_argument(
        "--limit",
        type=int,
        default=20,
        help="Max findings to print with --list (default: 20)",
    )
    args = parser.parse_args()

    before_path = Path(args.report)
    if not before_path.exists():
        raise FileNotFoundError(f"Report not found: {before_path}")

    before_data = load_report(before_path)
    before_results = before_data.get("results", [])

    print(f"Report: {before_path}")
    print_summary(before_results)

    if args.list:
        print(f"Listing findings (max {args.limit}):")
        print()
        list_findings(before_results, args.limit)

    if args.after:
        after_path = Path(args.after)
        if not after_path.exists():
            raise FileNotFoundError(f"Comparison report not found: {after_path}")
        after_data = load_report(after_path)
        after_results = after_data.get("results", [])

        print("Before/After:")
        print(f"  Before: {len(before_results)}")
        print(f"  After : {len(after_results)}")
        print(f"  Fixed : {len(before_results) - len(after_results)}")


if __name__ == "__main__":
    main()
