"""Measure the unchanged EvidenceGate prototype; retain raw observations."""

from __future__ import annotations

from copy import deepcopy
import csv
from datetime import datetime, timedelta, timezone
import hashlib
import io
from itertools import product
import json
import os
from pathlib import Path
import platform
from statistics import median, quantiles
import subprocess
import sys
from time import perf_counter_ns, get_clock_info
import unittest

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
REPO = ROOT.parent
TOOL = REPO / "evidencegate"
sys.path.insert(0, str(TOOL))

from evidencegate import __version__
from evidencegate.benchmark import decisions, make_cases
from evidencegate.core import evaluate, iso, parse_json
from evidencegate.demo import demo_bundle

NOW = datetime(2026, 10, 25, 9, 0, tzinfo=timezone.utc)
MODES = ["presence_only", "without_artifact_binding", "evidencegate"]
CATEGORIES = {
    "missing_provenance": "Missing evidence", "missing_sbom": "Missing evidence", "missing_scan": "Missing evidence",
    "empty_sbom": "Record structure", "scan_not_object": "Record structure", "partial_scan": "Record structure",
    "unknown_severity_label": "Record structure", "unsupported_sbom": "Record structure", "unsupported_provenance": "Record structure",
    "reused_provenance": "Artifact binding", "reused_sbom": "Artifact binding", "reused_scan": "Artifact binding",
    "missing_artifact_hash": "Artifact binding", "conflicting_artifact_hashes": "Artifact binding",
    "unapproved_builder": "Builder and source", "wrong_source": "Builder and source", "conflicting_source": "Builder and source",
    "stale_scan": "Scan time", "future_scan": "Scan time", "missing_scan_date": "Scan time",
    "critical_vulnerability": "Vulnerability policy", "high_vulnerability": "Vulnerability policy",
}


def save_json(name, value):
    path = ROOT / "results" / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2)+"\n", encoding="utf-8")


def save_csv(name, rows):
    with (ROOT/"results"/name).open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]), lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def run_cases(dataset, cases):
    rows, checks = [], []
    for case in cases:
        b = case["bundle"]
        report = evaluate(b["artifact_sha256"], b["provenance"], b["sbom"], b["scan"], b["policy"], now=NOW)
        for mode, decision in decisions(b, report).items():
            rows.append({"dataset": dataset, "case_id": case["id"], "category": case["category"],
                         "expected": case["expected"], "mode": mode, "decision": decision})
        checks.extend({"dataset": dataset, "case_id": case["id"], "rule": c["id"], "status": c["status"]} for c in report["checks"])
    metrics = []
    for mode in MODES:
        selected = [r for r in rows if r["mode"] == mode]
        tp = sum(r["expected"] == "BLOCK" and r["decision"] == "BLOCK" for r in selected)
        fn = sum(r["expected"] == "BLOCK" and r["decision"] == "PASS" for r in selected)
        fp = sum(r["expected"] == "PASS" and r["decision"] == "BLOCK" for r in selected)
        tn = sum(r["expected"] == "PASS" and r["decision"] == "PASS" for r in selected)
        metrics.append({"dataset": dataset, "mode": mode, "true_blocks": tp, "false_accepts": fn,
                        "false_blocks": fp, "true_accepts": tn,
                        "precision": tp/(tp+fp) if tp+fp else None,
                        "recall": tp/(tp+fn) if tp+fn else None,
                        "f1": 2*tp/(2*tp+fn+fp) if 2*tp+fn+fp else None})
    return rows, checks, metrics


def factorial_cases():
    cases = []
    names = ["provenance_mismatch", "sbom_mismatch", "scan_mismatch", "unapproved_builder", "stale_scan", "critical_finding"]
    for number, flags in enumerate(product([False, True], repeat=6)):
        b = demo_bundle(NOW)
        if flags[0]: b["provenance"]["subject"][0]["digest"]["sha256"] = "a"*64
        if flags[1]: b["sbom"]["metadata"]["component"]["hashes"][0]["content"] = "b"*64
        if flags[2]: b["scan"]["subject"]["sha256"] = "c"*64
        if flags[3]: b["provenance"]["predicate"]["runDetails"]["builder"]["id"] = "https://example.org/unapproved"
        if flags[4]: b["scan"]["scanned_at"] = iso(NOW-timedelta(hours=73))
        if flags[5]: b["scan"]["vulnerabilities"] = [{"id": "SYNTHETIC-CRITICAL", "package": "example", "severity": "CRITICAL"}]
        cases.append({"id": f"F{number:02d}", "category": "Factorial combination", "flags": dict(zip(names, flags)),
                      "expected": "BLOCK" if any(flags) else "PASS", "bundle": b})
    return cases


def run_unit_tests():
    suite = unittest.defaultTestLoader.discover(str(TOOL/"tests"))
    groups = {}

    def walk(node):
        for test in node:
            if isinstance(test, unittest.TestSuite):
                walk(test)
            else:
                groups[test.__class__.__name__] = groups.get(test.__class__.__name__, 0)+1

    walk(suite)
    buffer = io.StringIO()
    result = unittest.TextTestRunner(stream=buffer, verbosity=2).run(suite)
    (ROOT/"results"/"unittest.log").write_text(buffer.getvalue(), encoding="utf-8")
    if not result.wasSuccessful():
        raise RuntimeError("Tool tests failed; see results/unittest.log")
    return {"tests_run": result.testsRun, "failures": len(result.failures), "errors": len(result.errors),
            "skipped": len(result.skipped), "groups": groups}


def run_timing(repeats=100, warmups=10):
    raw_rows, summaries = [], []
    for count in [0, 100, 1000, 10000]:
        b = demo_bundle(NOW)
        b["sbom"]["components"] = [{"type": "library", "name": f"package-{i}", "version": "1.0.0"} for i in range(count)]
        b["scan"]["vulnerabilities"] = [{"id": f"SYNTHETIC-{i:06d}", "package": f"package-{i}", "severity": "LOW"} for i in range(count)]
        payload = json.dumps(b, separators=(",", ":")).encode()
        assert len(payload) < 8*1024*1024
        for repetition in range(-warmups, repeats):
            t0 = perf_counter_ns()
            parsed = parse_json(payload)
            t1 = perf_counter_ns()
            report = evaluate(parsed["artifact_sha256"], parsed["provenance"], parsed["sbom"], parsed["scan"], parsed["policy"], now=NOW)
            t2 = perf_counter_ns()
            assert report["decision"] == "PASS"
            if repetition >= 0:
                raw_rows.append({"records_each": count, "input_bytes": len(payload), "repetition": repetition,
                                 "parse_ms": (t1-t0)/1_000_000, "evaluate_ms": (t2-t1)/1_000_000,
                                 "parse_and_evaluate_ms": (t2-t0)/1_000_000})
        selected = [r for r in raw_rows if r["records_each"] == count]
        entry = {"records_each": count, "input_bytes": len(payload), "repeats": repeats, "warmups": warmups}
        for field in ["parse_ms", "evaluate_ms", "parse_and_evaluate_ms"]:
            values = [r[field] for r in selected]
            quartiles = quantiles(values, n=4, method="inclusive")
            entry[field+"_median"] = median(values)
            entry[field+"_q1"] = quartiles[0]
            entry[field+"_q3"] = quartiles[2]
        summaries.append(entry)
    return raw_rows, summaries


def residual_controls():
    descriptions = {
        "forged_consistent_claims": "All visible declarations match policy, but their claimed producer is not authenticated.",
        "omitted_critical_finding": "A synthetic external truth label says a critical finding exists, but the supplied scan omits it.",
    }
    rows = []
    for name, description in descriptions.items():
        b = demo_bundle(NOW)
        report = evaluate(b["artifact_sha256"], b["provenance"], b["sbom"], b["scan"], b["policy"], now=NOW)
        rows.append({"control": name, "description": description, "observed_decision": report["decision"],
                     "checks_passed": report["summary"]["passed"], "in_confusion_metrics": False,
                     "interpretation": "Outside the checker’s observability; not a simulated real exploit."})
    return rows


def environment():
    cpu = "not recorded"
    try:
        cpu = next(line.split(":", 1)[1].strip() for line in Path("/proc/cpuinfo").read_text().splitlines() if line.startswith("model name"))
    except (OSError, StopIteration):
        pass
    source_files = sorted((TOOL/"evidencegate").rglob("*.py"))+sorted((TOOL/"tests").glob("*.py"))
    hashes = {p.relative_to(REPO).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest() for p in source_files}
    try:
        revision = subprocess.check_output(["git", "log", "-1", "--format=%H", "--", "evidencegate"],
                                           cwd=REPO, text=True, stderr=subprocess.DEVNULL).strip()
        revision_origin = "Git history of the evaluated tool folder"
    except (OSError, subprocess.CalledProcessError):
        # The standalone download has no .git directory. Preserve its recorded
        # source revision only if every evaluated source hash still agrees.
        prior_path = ROOT/"results"/"environment.json"
        prior = json.loads(prior_path.read_text()) if prior_path.exists() else {}
        revision = prior.get("evaluated_git_commit", "source archive") if prior.get("source_sha256") == hashes else "source archive"
        revision_origin = "Recorded archive revision with matching hashes; Git metadata unavailable"
    return {"measured_at_utc": iso(datetime.now(timezone.utc)), "fixed_assessment_time": iso(NOW),
            "tool_version": __version__, "evaluated_git_commit": revision, "revision_origin": revision_origin,
            "python": platform.python_version(), "platform": platform.platform(), "machine": platform.machine(),
            "cpu_model": cpu, "visible_logical_cpus": os.cpu_count(),
            "affinity_cpus": len(os.sched_getaffinity(0)) if hasattr(os, "sched_getaffinity") else None,
            "clock": "perf_counter_ns", "clock_resolution_seconds": get_clock_info("perf_counter").resolution,
            "execution_context": "Shared cloud environment; no CPU isolation, memory profiling, or dedicated-machine control.",
            "source_sha256": hashes}


def main():
    (ROOT/"results").mkdir(parents=True, exist_ok=True)
    original = make_cases(NOW, 7)
    for case in original:
        case["category"] = CATEGORIES.get(case["id"], "Valid control")
    factorial = factorial_cases()
    all_rows, all_checks, metrics = [], [], []
    for name, cases in [("fixture27", original), ("factorial64", factorial)]:
        rows, checks, measured = run_cases(name, cases)
        all_rows += rows
        all_checks += checks
        metrics += measured
    tests = run_unit_tests()
    raw_timing, timing_summary = run_timing()
    save_json("cases.json", {"fixture27": original, "factorial64": factorial})
    save_csv("decisions.csv", all_rows)
    save_csv("rule_outcomes.csv", all_checks)
    save_csv("comparison_metrics.csv", metrics)
    save_csv("timing_raw.csv", raw_timing)
    save_csv("timing_summary.csv", timing_summary)
    save_json("unit_tests.json", tests)
    save_json("residual_controls.json", residual_controls())
    save_json("environment.json", environment())
    summary = {"datasets": {"fixture27": {"cases": 27, "valid": 5, "faulty": 22},
                             "factorial64": {"cases": 64, "valid": 1, "faulty": 63}},
               "metrics": metrics, "unit_tests": tests, "timing": timing_summary,
               "design": "Controlled synthetic rule evaluation, not independent field validation.",
               "timing_scope": "JSON parsing plus full in-memory evaluation; excludes I/O, hashing, scanning, signature verification, report serialization, network, and deployment."}
    save_json("summary.json", summary)
    print(f"Measured 91 synthetic cases across three modes; {tests['tests_run']} tests passed; {len(raw_timing)} timing observations saved.")


if __name__ == "__main__":
    main()
