"""Check traceability of saved measurements and manuscript assets."""

import csv
import hashlib
import json
from pathlib import Path
import re
from statistics import median, quantiles

ROOT = Path(__file__).resolve().parents[1]


def read_csv(name):
    with (ROOT/"results"/name).open() as handle:
        return list(csv.DictReader(handle))


def main():
    summary = json.loads((ROOT/"results"/"summary.json").read_text())
    cases = json.loads((ROOT/"results"/"cases.json").read_text())
    rows = read_csv("decisions.csv")
    checks = read_csv("rule_outcomes.csv")
    assert len(rows) == (27+64)*3
    assert len(checks) == (27+64)*10
    for dataset,details in summary["datasets"].items():
        assert len(cases[dataset]) == details["cases"]
        assert sum(c["expected"] == "PASS" for c in cases[dataset]) == details["valid"]
        labels = {c["id"]: c["expected"] for c in cases[dataset]}
        for row in [r for r in rows if r["dataset"] == dataset]:
            assert row["expected"] == labels[row["case_id"]]
    for expected in summary["metrics"]:
        selected = [r for r in rows if r["dataset"] == expected["dataset"] and r["mode"] == expected["mode"]]
        for name,gold,observed in [("true_blocks","BLOCK","BLOCK"),("false_accepts","BLOCK","PASS"),
                                    ("false_blocks","PASS","BLOCK"),("true_accepts","PASS","PASS")]:
            assert sum(r["expected"] == gold and r["decision"] == observed for r in selected) == expected[name]
    raw = read_csv("timing_raw.csv")
    assert len(raw) == 400
    for expected in summary["timing"]:
        selected = [r for r in raw if int(r["records_each"]) == expected["records_each"]]
        assert len(selected) == 100
        for field in ["parse_ms", "evaluate_ms", "parse_and_evaluate_ms"]:
            values = [float(r[field]) for r in selected]
            assert abs(median(values)-expected[field+"_median"]) < 1e-10
            quartiles = quantiles(values,n=4,method="inclusive")
            assert abs(quartiles[0]-expected[field+"_q1"]) < 1e-10
            assert abs(quartiles[2]-expected[field+"_q3"]) < 1e-10
    assert summary["unit_tests"]["tests_run"] == 31
    assert all(summary["unit_tests"][k] == 0 for k in ["failures","errors","skipped"])
    browser = json.loads((ROOT/"results"/"browser_tests.json").read_text())
    assert browser["passed"] == len(browser["tests"]) == 10
    assert all(t["result"] == "PASS" for t in browser["tests"])
    assert not browser["javascript_errors"]
    environment = json.loads((ROOT/"results"/"environment.json").read_text())
    for name,expected in environment["source_sha256"].items():
        assert hashlib.sha256((ROOT.parent/name).read_bytes()).hexdigest() == expected,name
    manuscript = (ROOT/"EvidenceGate_Research_Paper.md").read_text()
    assert len(re.findall(r'^\*\*Figure \d+\.',manuscript,re.M)) == 6
    assert len(re.findall(r'^\*\*Table \d+\.',manuscript,re.M)) == 7
    for filename in re.findall(r'!\[[^\n]*\]\(([^)]+)\)',manuscript):
        assert (ROOT/filename).is_file(),filename
    assert len(list((ROOT/"tables").glob("table_*.csv"))) == 7
    print("PASS: dataset labels, 273 decisions, 910 rule results, timing summaries, 31 tests, 10 browser checks, source hashes, and paper assets agree.")


if __name__ == "__main__":
    main()
