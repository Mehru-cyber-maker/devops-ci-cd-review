from copy import deepcopy
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from evidencegate.adapters import import_trivy
from evidencegate.benchmark import decisions, make_cases, run_benchmark
from evidencegate.core import InputError, Policy, evaluate, file_digest, iso, parse_json
from evidencegate.demo import ARTIFACT, DEMO_DIGEST, demo_bundle
from evidencegate.reporting import csv_cell, write_report

NOW = datetime(2026, 10, 25, 9, 0, tzinfo=timezone.utc)


class CoreTests(unittest.TestCase):
    def setUp(self):
        self.b = demo_bundle(NOW)

    def check(self, bundle=None, now=NOW):
        b = bundle or self.b
        return evaluate(b["artifact_sha256"], b["provenance"], b["sbom"], b["scan"], b["policy"], now=now)

    def failed(self, report):
        return {c["id"] for c in report["checks"] if c["status"] == "fail"}

    def test_consistent_records_pass_all_ten_rules(self):
        report = self.check()
        self.assertEqual(report["decision"], "PASS")
        self.assertEqual(report["summary"], {"passed": 10, "failed": 0, "total": 10})

    def test_hashing_changed_artifact_invalidates_all_bindings(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)/"release.bin"
            path.write_bytes(ARTIFACT)
            self.assertEqual(file_digest(path), DEMO_DIGEST)
            path.write_bytes(ARTIFACT+b"changed\n")
            self.b["artifact_sha256"] = file_digest(path)
            self.assertEqual(self.failed(self.check()), {"EG002", "EG006", "EG008"})

    def test_reused_clean_scan_passes_ablation_but_full_check_blocks(self):
        self.b["scan"]["subject"]["sha256"] = "a"*64
        modes = decisions(self.b, self.check())
        self.assertEqual(modes["presence_only"], "PASS")
        self.assertEqual(modes["without_artifact_binding"], "PASS")
        self.assertEqual(modes["evidencegate"], "BLOCK")

    def test_each_missing_record_blocks(self):
        for name in ["provenance", "sbom", "scan"]:
            with self.subTest(name=name):
                b = deepcopy(self.b)
                b[name] = None
                self.assertEqual(self.check(b)["decision"], "BLOCK")

    def test_scan_at_maximum_age_is_accepted(self):
        self.b["scan"]["scanned_at"] = iso(NOW-timedelta(hours=72))
        self.assertEqual(self.check()["decision"], "PASS")
        self.b["scan"]["scanned_at"] = iso(NOW-timedelta(hours=72, seconds=1))
        self.assertIn("EG009", self.failed(self.check()))

    def test_future_clock_skew_boundary(self):
        self.b["scan"]["scanned_at"] = iso(NOW+timedelta(minutes=5))
        self.assertEqual(self.check()["decision"], "PASS")
        self.b["scan"]["scanned_at"] = iso(NOW+timedelta(minutes=5, seconds=1))
        self.assertIn("EG009", self.failed(self.check()))

    def test_naive_scan_time_is_rejected_and_offset_is_accepted(self):
        self.b["scan"]["scanned_at"] = "2026-10-25T08:50:00"
        self.assertIn("EG009", self.failed(self.check()))
        self.b["scan"]["scanned_at"] = "2026-10-25T13:50:00+05:00"
        self.assertEqual(self.check()["decision"], "PASS")

    def test_case_insensitive_hex(self):
        self.b["artifact_sha256"] = DEMO_DIGEST.upper()
        self.b["provenance"]["subject"][0]["digest"]["sha256"] = DEMO_DIGEST.upper()
        self.assertEqual(self.check()["decision"], "PASS")

    def test_component_hash_is_not_taken_from_nested_dependency(self):
        self.b["sbom"]["components"][0]["hashes"] = [{"alg": "SHA-256", "content": DEMO_DIGEST}]
        self.b["sbom"]["metadata"]["component"]["hashes"] = []
        self.assertIn("EG006", self.failed(self.check()))

    def test_conflicting_hashes_and_source_commits_block(self):
        self.b["sbom"]["metadata"]["component"]["hashes"].append({"alg": "SHA-256", "content": "0"*64})
        self.b["provenance"]["predicate"]["buildDefinition"]["resolvedDependencies"].append(
            {"uri": self.b["policy"]["expected_source"]["uri"], "digest": {"gitCommit": "2"*40}})
        self.assertEqual(self.failed(self.check()), {"EG004", "EG006"})

    def test_malformed_nested_types_block_without_crashing(self):
        for value in [[], {}, None, True, 0, 1.5]:
            with self.subTest(value=value):
                b = deepcopy(self.b)
                b["sbom"]["specVersion"] = value
                b["scan"]["vulnerabilities"] = [{"id": "x", "package": "x", "severity": value}]
                self.assertEqual(self.check(b)["decision"], "BLOCK")

    def test_known_vulnerability_does_not_disappear_on_wrong_artifact(self):
        self.b["scan"]["subject"]["sha256"] = "0"*64
        self.b["scan"]["vulnerabilities"] = [{"id": "SYNTHETIC", "package": "x", "severity": "HIGH"}]
        self.assertEqual(self.failed(self.check()), {"EG008", "EG010"})

    def test_policy_unknown_fields_and_boolean_hours_are_errors(self):
        for change in [{"max_scan_age_hours": True}, {"allow_missing_scan": True}, {"allowed_builders": []}]:
            p = deepcopy(self.b["policy"])
            p.update(change)
            with self.subTest(change=change), self.assertRaises(InputError):
                Policy.from_dict(p)

    def test_raw_dsse_envelope_is_not_silently_trusted(self):
        self.b["provenance"] = {"payloadType": "application/vnd.in-toto+json", "payload": "e30=", "signatures": []}
        self.assertIn("EG001", self.failed(self.check()))

    def test_forged_but_consistent_claims_remain_a_documented_limit(self):
        # The fixtures themselves are unsigned claims. The checker cannot authenticate them.
        report = self.check()
        self.assertEqual(report["decision"], "PASS")
        self.assertTrue(any("does not verify signatures" in s for s in report["limitations"]))

    def test_strict_json_rejects_duplicate_keys_and_nonfinite_constants(self):
        for raw in [b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":Infinity}', b'\xff', b'[] trailing', b'{"x":'+b'1'*5000+b'}']:
            with self.subTest(raw=raw), self.assertRaises(InputError):
                parse_json(raw)

    def test_every_labeled_mutation_and_deterministic_dataset(self):
        cases = make_cases(NOW, 7)
        self.assertEqual(cases, make_cases(NOW, 7))
        self.assertEqual(len(cases), 27)
        for case in cases:
            with self.subTest(case=case["id"]):
                self.assertEqual(self.check(case["bundle"])["decision"], case["expected"])

    def test_benchmark_records_computed_confusion_counts(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = run_benchmark(Path(tmp), now=NOW, repeats=2)
            self.assertEqual(result["metrics"]["evidencegate"]["true_blocks"], 22)
            self.assertEqual(result["metrics"]["without_artifact_binding"]["false_accepts"], 5)
            self.assertEqual(result["metrics"]["evidencegate"]["true_accepts"], 5)
            self.assertTrue((Path(tmp)/"results.csv").exists())

    def test_reports_escape_untrusted_identifiers(self):
        self.b["scan"]["vulnerabilities"] = [{"id": '<script>alert(1)</script>', "package": "=2+2", "severity": "HIGH"}]
        with tempfile.TemporaryDirectory() as tmp:
            write_report(self.check(), Path(tmp))
            html = (Path(tmp)/"index.html").read_text()
            self.assertNotIn("<script>alert(1)</script>", html)
            self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", html)
            self.assertEqual(json.loads((Path(tmp)/"report.json").read_text())["decision"], "BLOCK")
        self.assertEqual(csv_cell("=2+2"), "'=2+2")


class TrivyTests(unittest.TestCase):
    def setUp(self):
        self.data = {"SchemaVersion": 2, "Metadata": {"RepoDigests": ["example.org/app@sha256:"+DEMO_DIGEST],
                     "ImageID": "sha256:"+"f"*64}, "Results": [{"Class": "os-pkgs", "Type": "debian",
                     "Vulnerabilities": [{"VulnerabilityID": "SYNTHETIC", "PkgName": "demo", "Severity": "HIGH"}]}]}

    def convert(self):
        return import_trivy(self.data, DEMO_DIGEST, iso(NOW), "test-version")

    def test_import_preserves_manifest_digest_and_finding(self):
        result = self.convert()
        self.assertEqual(result["subject"]["sha256"], DEMO_DIGEST)
        self.assertEqual(result["vulnerabilities"][0]["severity"], "HIGH")

    def test_image_id_cannot_substitute_for_manifest_digest(self):
        self.data["Metadata"] = {"ImageID": "sha256:"+DEMO_DIGEST}
        with self.assertRaises(InputError):
            self.convert()

    def test_wrong_manifest_digest_rejected(self):
        self.data["Metadata"]["RepoDigests"] = ["example.org/app@sha256:"+"0"*64]
        with self.assertRaises(InputError):
            self.convert()

    def test_empty_or_nonpackage_results_do_not_imply_clean_scan(self):
        for results in [[], [{"Class": "secret"}], None]:
            self.data["Results"] = results
            with self.subTest(results=results), self.assertRaises(InputError):
                self.convert()

    def test_missing_vulnerabilities_field_is_clean_only_under_import_confirmation(self):
        self.data["Results"][0].pop("Vulnerabilities")
        self.assertEqual(self.convert()["vulnerabilities"], [])


if __name__ == "__main__":
    unittest.main()
