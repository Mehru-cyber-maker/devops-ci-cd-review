"""Labeled synthetic mutations and explicit, limited baseline comparisons."""

from copy import deepcopy
import csv
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import random
from statistics import median
from time import perf_counter_ns

from .core import evaluate, iso
from .demo import demo_bundle

BINDING_RULES = {"EG002", "EG006", "EG008"}


def make_cases(now: datetime, seed: int = 7) -> list[dict]:
    rng = random.Random(seed)
    cases = []
    base = demo_bundle(now)
    other_digest = f"{rng.getrandbits(256):064x}"

    def add(name, fault, change=None):
        bundle = deepcopy(base)
        if change:
            change(bundle)
        cases.append({"id": name, "kind": "fault" if fault else "valid", "expected": "BLOCK" if fault else "PASS",
                      "data_origin": "synthetic mutation, not a real incident", "bundle": bundle})

    def vulnerability(severity):
        return lambda b: b["scan"]["vulnerabilities"].append(
            {"id": "SYNTHETIC-001", "package": "example-package", "severity": severity})

    add("clean", False)
    add("low_severity", False, vulnerability("LOW"))
    add("medium_severity", False, vulnerability("MEDIUM"))
    add("multiple_subjects", False, lambda b: b["provenance"]["subject"].append(
        {"name": "other-artifact", "digest": {"sha256": other_digest}}))
    add("additional_dependency", False, lambda b: b["provenance"]["predicate"]["buildDefinition"]["resolvedDependencies"].append(
        {"uri": "git+https://example.org/another.git", "digest": {"gitCommit": "2" * 40}}))
    for name in ["provenance", "sbom", "scan"]:
        add(f"missing_{name}", True, lambda b, n=name: b.update({n: None}))
    add("empty_sbom", True, lambda b: b.update(sbom={}))
    add("scan_not_object", True, lambda b: b.update(scan=[]))
    add("reused_provenance", True, lambda b: b["provenance"]["subject"][0]["digest"].update(sha256=other_digest))
    add("reused_sbom", True, lambda b: b["sbom"]["metadata"]["component"]["hashes"][0].update(content=other_digest))
    add("reused_scan", True, lambda b: b["scan"]["subject"].update(sha256=other_digest))
    add("unapproved_builder", True, lambda b: b["provenance"]["predicate"]["runDetails"]["builder"].update(id="https://example.org/unapproved"))
    add("wrong_source", True, lambda b: b["provenance"]["predicate"]["buildDefinition"]["resolvedDependencies"][0]["digest"].update(gitCommit="2" * 40))
    add("stale_scan", True, lambda b: b["scan"].update(scanned_at=iso(now-timedelta(hours=73))))
    add("future_scan", True, lambda b: b["scan"].update(scanned_at=iso(now+timedelta(minutes=6))))
    add("critical_vulnerability", True, vulnerability("CRITICAL"))
    add("high_vulnerability", True, vulnerability("HIGH"))
    add("partial_scan", True, lambda b: b["scan"].update(status="partial"))
    add("unknown_severity_label", True, vulnerability("INVALID"))
    add("unsupported_sbom", True, lambda b: b["sbom"].update(specVersion="1.4"))
    add("unsupported_provenance", True, lambda b: b["provenance"].update(predicateType="unsupported"))
    add("missing_artifact_hash", True, lambda b: b["sbom"]["metadata"]["component"].update(hashes=[]))
    add("conflicting_artifact_hashes", True, lambda b: b["sbom"]["metadata"]["component"]["hashes"].append(
        {"alg": "SHA-256", "content": other_digest}))
    add("missing_scan_date", True, lambda b: b["scan"].pop("scanned_at"))
    add("conflicting_source", True, lambda b: b["provenance"]["predicate"]["buildDefinition"]["resolvedDependencies"].append(
        {"uri": b["policy"]["expected_source"]["uri"], "digest": {"gitCommit": "3" * 40}}))
    return cases


def decisions(bundle: dict, report: dict) -> dict[str, str]:
    present = all(bundle.get(n) is not None for n in ["provenance", "sbom", "scan"])
    independent_failed = any(c["status"] == "fail" and c["id"] not in BINDING_RULES for c in report["checks"])
    return {"presence_only": "PASS" if present else "BLOCK",
            "without_artifact_binding": "BLOCK" if independent_failed else "PASS",
            "evidencegate": report["decision"]}


def run_benchmark(directory: Path, *, now: datetime | None = None, seed: int = 7, repeats: int = 5) -> dict:
    now = now or datetime.now(timezone.utc)
    cases = make_cases(now, seed)
    rows, timings = [], []
    for case in cases:
        b = case["bundle"]
        elapsed = []
        for _ in range(repeats):
            start = perf_counter_ns()
            report = evaluate(b["artifact_sha256"], b["provenance"], b["sbom"], b["scan"], b["policy"], now=now)
            elapsed.append((perf_counter_ns()-start)/1_000_000)
        timings.append(median(elapsed))
        for mode, decision in decisions(b, report).items():
            failed = [c["id"] for c in report["checks"] if c["status"] == "fail"
                      and (mode != "without_artifact_binding" or c["id"] not in BINDING_RULES)] if mode != "presence_only" else []
            rows.append({"case_id": case["id"], "kind": case["kind"], "expected": case["expected"], "mode": mode,
                         "decision": decision, "correct": decision == case["expected"], "failed_rules": ";".join(failed)})
    metrics = {}
    for mode in ["presence_only", "without_artifact_binding", "evidencegate"]:
        subset = [r for r in rows if r["mode"] == mode]
        tp = sum(r["expected"] == "BLOCK" and r["decision"] == "BLOCK" for r in subset)
        fn = sum(r["expected"] == "BLOCK" and r["decision"] == "PASS" for r in subset)
        fp = sum(r["expected"] == "PASS" and r["decision"] == "BLOCK" for r in subset)
        tn = sum(r["expected"] == "PASS" and r["decision"] == "PASS" for r in subset)
        precision = tp/(tp+fp) if tp+fp else None
        recall = tp/(tp+fn) if tp+fn else None
        metrics[mode] = {"true_blocks": tp, "false_accepts": fn, "false_blocks": fp, "true_accepts": tn,
                         "precision": precision, "recall": recall,
                         "f1": 2*tp/(2*tp+fp+fn) if 2*tp+fp+fn else None}
    summary = {"dataset": "EvidenceGate synthetic mutations v1", "seed": seed, "assessed_at": iso(now),
               "cases": len(cases), "valid_cases": sum(c["kind"] == "valid" for c in cases),
               "fault_cases": sum(c["kind"] == "fault" for c in cases), "repeats": repeats,
               "full_evaluator_median_ms": median(timings), "metrics": metrics,
               "timing_scope": "In-memory full evaluation only; no file I/O, scanning, signature verification, or baseline timing.",
               "limits": "Seeded faults exercise known rules. Not independent validation, real-world detection accuracy, or proof of novelty."}
    directory.mkdir(parents=True, exist_ok=True)
    for name, value in [("cases.json", cases), ("summary.json", summary)]:
        (directory/name).write_text(json.dumps(value, indent=2)+"\n", encoding="utf-8")
    with (directory/"results.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]), lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)
    table = "\n".join(f"| {name} | {m['true_blocks']} | {m['false_accepts']} | {m['false_blocks']} | {m['true_accepts']} |" for name,m in metrics.items())
    (directory/"evaluation.md").write_text(f"""# Synthetic demonstration results

Generated by running EvidenceGate on {len(cases)} labeled synthetic cases: {summary['valid_cases']} valid and {summary['fault_cases']} faulty.

| Mode | True blocks | False accepts | False blocks | True accepts |
|:--|--:|--:|--:|--:|
{table}

`presence_only` checks document availability. `without_artifact_binding` removes EG002, EG006, and EG008 from the full decision. Neither is claimed to represent an existing commercial product.

Timing: {summary['full_evaluator_median_ms']:.4f} ms median of per-case medians; {repeats} repetitions per case. Only in-memory rule evaluation was timed. These small synthetic timings cannot establish production performance.

The fault labels follow the construction of each example. Perfect detection of these known mutations would show rule behavior, not general security effectiveness. Use an independently labeled external dataset for research claims.

Seed: {seed}. Assessment time: {iso(now)}. See `cases.json` for the full constructed inputs and labels, and `results.csv` for every decision.
""", encoding="utf-8")
    return summary
