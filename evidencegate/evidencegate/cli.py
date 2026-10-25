"""Command-line interface with CI-friendly exit codes."""

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import sys

from . import __version__
from .adapters import import_trivy
from .benchmark import run_benchmark
from .core import InputError, evaluate, file_digest, read_json, timestamp
from .demo import write_demo
from .reporting import write_report


def _time(args):
    return timestamp(args.at) if args.at else datetime.now(timezone.utc)


def _positive(value):
    result = int(value)
    if not 1 <= result <= 1000:
        raise argparse.ArgumentTypeError("must be between 1 and 1000")
    return result


def parser():
    p = argparse.ArgumentParser(description="Offline checks for artifact-bound CI/CD security evidence.")
    p.add_argument("--version", action="version", version=__version__)
    commands = p.add_subparsers(dest="command", required=True)
    check = commands.add_parser("check", help="Check supplied evidence; returns 0=PASS, 1=BLOCK, 2=input error")
    artifact = check.add_mutually_exclusive_group(required=True)
    artifact.add_argument("--artifact", type=Path, help="Hash the exact bytes of a local release file")
    artifact.add_argument("--sha256", help="Expected SHA-256, selected independently of the evidence")
    check.add_argument("--policy", type=Path, required=True)
    for name in ["provenance", "sbom", "scan"]:
        check.add_argument("--"+name, type=Path, help="Optional path; omission produces blocking checks")
    check.add_argument("--output-dir", type=Path, default=Path("outputs/check"))
    check.add_argument("--at", help="Explicit assessment time for reproducible audits; default is current UTC")
    demo = commands.add_parser("demo", help="Generate synthetic clean and mismatched examples")
    demo.add_argument("--output-dir", type=Path, default=Path("outputs/demo"))
    demo.add_argument("--at", help="ISO-8601 time for a reproducible synthetic demo")
    bench = commands.add_parser("benchmark", help="Evaluate labeled synthetic mutations and ablation baselines")
    bench.add_argument("--output-dir", type=Path, default=Path("outputs/benchmark"))
    bench.add_argument("--seed", type=int, default=7)
    bench.add_argument("--repeats", type=_positive, default=5)
    bench.add_argument("--at", help="ISO-8601 time for a reproducible synthetic dataset")
    serve = commands.add_parser("serve", help="Open the local dashboard at http://127.0.0.1:8765")
    serve.add_argument("--port", type=int, default=8765)
    trivy = commands.add_parser("import-trivy", help="Normalize OCI-image Trivy JSON using its manifest digest")
    trivy.add_argument("--input", type=Path, required=True)
    trivy.add_argument("--sha256", required=True, help="OCI manifest digest from Metadata.RepoDigests")
    trivy.add_argument("--scanned-at", required=True, help="Actual scan time captured by your trusted job")
    trivy.add_argument("--scanner-version", required=True)
    trivy.add_argument("--confirm-vulnerability-scan", action="store_true", required=True,
                       help="Confirm a successful run with --scanners vuln; JSON alone cannot prove coverage")
    trivy.add_argument("--output", type=Path, required=True)
    return p


def main(argv=None):
    args = parser().parse_args(argv)
    try:
        if args.command == "check":
            digest = file_digest(args.artifact) if args.artifact else args.sha256
            docs = [read_json(getattr(args, n)) if getattr(args, n) else None for n in ["provenance", "sbom", "scan"]]
            report = evaluate(digest, *docs, read_json(args.policy), now=_time(args))
            write_report(report, args.output_dir)
            print(f"{report['decision']}: {report['summary']['passed']}/10 checks passed")
            for c in report["checks"]:
                if c["status"] == "fail":
                    print(f"  {c['id']}: {c['message']}")
            print(f"Report: {args.output_dir / 'index.html'}")
            print("Supplied claims checked; signatures and software safety are not verified.")
            return 0 if report["decision"] == "PASS" else 1
        if args.command == "demo":
            now = _time(args)
            bundle = write_demo(args.output_dir / "inputs", now)
            clean = evaluate(bundle["artifact_sha256"], bundle["provenance"], bundle["sbom"], bundle["scan"], bundle["policy"], now=now)
            write_report(clean, args.output_dir / "clean")
            bundle["scan"]["subject"]["sha256"] = "0" * 64
            (args.output_dir / "inputs" / "mismatched-scan.json").write_text(json.dumps(bundle["scan"], indent=2)+"\n", encoding="utf-8")
            mismatch = evaluate(bundle["artifact_sha256"], bundle["provenance"], bundle["sbom"], bundle["scan"], bundle["policy"], now=now)
            write_report(mismatch, args.output_dir / "mismatch")
            print(f"Synthetic clean example: {clean['decision']} · {args.output_dir / 'clean' / 'index.html'}")
            print(f"Synthetic reused-scan example: {mismatch['decision']} · {args.output_dir / 'mismatch' / 'index.html'}")
            print("These are generated fixtures; no actual scan was performed.")
            return 0
        if args.command == "benchmark":
            result = run_benchmark(args.output_dir, now=_time(args), seed=args.seed, repeats=args.repeats)
            print(f"Evaluated {result['cases']} synthetic cases across three modes.")
            print(f"Results: {args.output_dir / 'evaluation.md'}")
            return 0
        if args.command == "import-trivy":
            result = import_trivy(read_json(args.input), args.sha256, args.scanned_at, args.scanner_version)
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(json.dumps(result, indent=2)+"\n", encoding="utf-8")
            print(f"Wrote {args.output}. Digest matched RepoDigests; timestamp and scan coverage remain externally asserted.")
            return 0
        if args.command == "serve":
            if not 1 <= args.port <= 65535:
                raise InputError("Port must be between 1 and 65535.")
            from .server import serve
            serve(args.port)
            return 0
    except (InputError, OSError) as exc:
        print(f"Input error: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 130
    return 2
