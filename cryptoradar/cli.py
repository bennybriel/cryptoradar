"""
cli.py — `cryptoradar` command-line entrypoint.

Usage:
    cryptoradar scan <path> [--name NAME] [-o report.html]
    cryptoradar scan-multi comp1:path1 comp2:path2 ... [-o report.html]
    cryptoradar cbom <path> [-o cbom.json]

Examples:
    cryptoradar scan ./identity-service --name "BenPay identity-service" -o report.html
    cryptoradar scan-multi "legacy-core:./core" "api-layer:./api" -o report.html \\
        --shelf-life 15 --migration-time 4
"""

from __future__ import annotations
import argparse
import sys

from . import scanner, report
from .detectors import Category

SEVERITY_NAMES = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}


def _max_severity(findings: list[dict]) -> int:
    real = [f for f in findings if f["category"] != Category.PQC_PRESENT.value]
    return max((f["severity"] for f in real), default=0)


def _apply_fail_on(all_findings: list[dict], fail_on: str) -> int:
    """Returns process exit code: 1 if a finding at/above the threshold exists."""
    if fail_on == "none":
        return 0
    threshold = SEVERITY_NAMES.get(fail_on)
    if threshold is None:
        print(f"[cryptoradar] Invalid --fail-on value '{fail_on}', "
              f"expected one of: none, {', '.join(SEVERITY_NAMES)}", file=sys.stderr)
        return 2
    worst = _max_severity(all_findings)
    if worst >= threshold:
        label = next(k for k, v in SEVERITY_NAMES.items() if v == worst)
        print(f"[cryptoradar] FAILING BUILD: highest finding severity is "
              f"'{label}', at/above --fail-on={fail_on} threshold.", file=sys.stderr)
        return 1
    return 0


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="cryptoradar",
                                 description="Crypto-agility & quantum-readiness scanner for fintech codebases.")
    sub = p.add_subparsers(dest="command", required=True)

    common_mosca = argparse.ArgumentParser(add_help=False)
    common_mosca.add_argument("--shelf-life", type=float, default=10.0,
                               help="Years the protected data/system must remain secure (Mosca X). Default 10.")
    common_mosca.add_argument("--migration-time", type=float, default=3.0,
                               help="Estimated years to complete migration once started (Mosca Y). Default 3.")
    common_mosca.add_argument("--z-low", type=int, default=8, help="Optimistic-for-attackers Z estimate (years). Default 8.")
    common_mosca.add_argument("--z-high", type=int, default=20, help="Conservative Z estimate (years). Default 20.")
    common_mosca.add_argument("--fail-on", default="none", choices=list(SEVERITY_NAMES) + ["none"],
                               help="Exit non-zero if a finding at/above this severity exists. "
                                    "Use in CI, e.g. --fail-on critical. Default: none (never fails).")

    scan_p = sub.add_parser("scan", parents=[common_mosca], help="Scan a single component/repo.")
    scan_p.add_argument("path", help="Path to the repository/component to scan.")
    scan_p.add_argument("--name", default=None, help="Display name for this component.")
    scan_p.add_argument("-o", "--output", default="cryptoradar_report.html", help="HTML report output path.")

    multi_p = sub.add_parser("scan-multi", parents=[common_mosca],
                              help="Scan several components together (e.g. legacy-core + api-layer + mobile).")
    multi_p.add_argument("components", nargs="+",
                          help="One or more NAME:PATH pairs, e.g. legacy-core:./core api:./api")
    multi_p.add_argument("-o", "--output", default="cryptoradar_report.html", help="HTML report output path.")

    cbom_p = sub.add_parser("cbom", help="Emit a machine-readable Crypto Bill of Materials (JSON) for a single path.")
    cbom_p.add_argument("path", help="Path to scan.")
    cbom_p.add_argument("--name", default=None)
    cbom_p.add_argument("-o", "--output", default="cbom.json")

    return p


def main(argv=None) -> int:
    args = _build_parser().parse_args(argv)

    if args.command == "scan":
        result = scanner.scan_repo(args.path, component_name=args.name)
        mosca_inputs = {"shelf_life_years": args.shelf_life, "migration_years": args.migration_time,
                         "z_low": args.z_low, "z_high": args.z_high}
        html_out = report.render_report(result, mosca_inputs)
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(html_out)
        print(f"[cryptoradar] Scanned {result['files_scanned']} files, "
              f"{len(result['findings'])} findings -> {args.output}")
        return _apply_fail_on(result["findings"], args.fail_on)

    elif args.command == "scan-multi":
        pairs = []
        for c in args.components:
            if ":" not in c:
                print(f"[cryptoradar] Invalid component spec '{c}', expected NAME:PATH", file=sys.stderr)
                return 2
            name, path = c.split(":", 1)
            pairs.append((name, path))
        result = scanner.scan_multi(pairs)
        mosca_inputs = {"shelf_life_years": args.shelf_life, "migration_years": args.migration_time,
                         "z_low": args.z_low, "z_high": args.z_high}
        html_out = report.render_report(result, mosca_inputs)
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(html_out)
        total_files = sum(c["files_scanned"] for c in result["components"])
        total_findings = sum(len(c["findings"]) for c in result["components"])
        print(f"[cryptoradar] Scanned {len(pairs)} components, {total_files} files, "
              f"{total_findings} findings -> {args.output}")
        all_findings = [f for c in result["components"] for f in c["findings"]]
        return _apply_fail_on(all_findings, args.fail_on)

    elif args.command == "cbom":
        result = scanner.scan_repo(args.path, component_name=args.name)
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(report.render_cbom_json(result))
        print(f"[cryptoradar] CBOM written -> {args.output}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
