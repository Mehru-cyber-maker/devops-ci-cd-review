"""Generate clearly labeled, synthetic data; never execute artifact contents."""

from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path

from .core import iso

ARTIFACT = b"EvidenceGate demonstration artifact.\nThis file is data, not an executable.\n"
DEMO_DIGEST = hashlib.sha256(ARTIFACT).hexdigest()


def demo_bundle(now: datetime | None = None) -> dict:
    now = now or datetime.now(timezone.utc)
    return {
        "artifact_sha256": DEMO_DIGEST,
        "policy": {
            "schema_version": 1,
            "allowed_builders": ["https://example.org/builders/student-demo/v1"],
            "expected_source": {"uri": "git+https://example.org/student/demo.git", "commit": "1" * 40},
            "max_scan_age_hours": 72,
            "blocked_severities": ["HIGH", "CRITICAL"],
        },
        "provenance": {
            "_type": "https://in-toto.io/Statement/v1",
            "subject": [{"name": "artifact.txt", "digest": {"sha256": DEMO_DIGEST}}],
            "predicateType": "https://slsa.dev/provenance/v1",
            "predicate": {
                "buildDefinition": {
                    "buildType": "https://example.org/build-types/student-demo/v1",
                    "externalParameters": {},
                    "resolvedDependencies": [{"uri": "git+https://example.org/student/demo.git",
                                               "digest": {"gitCommit": "1" * 40}}],
                },
                "runDetails": {"builder": {"id": "https://example.org/builders/student-demo/v1"}},
            },
        },
        "sbom": {
            "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
            "metadata": {"component": {"type": "file", "name": "artifact.txt",
                                       "hashes": [{"alg": "SHA-256", "content": DEMO_DIGEST}]}},
            "components": [{"type": "library", "name": "synthetic-example", "version": "1.0.0"}],
        },
        "scan": {
            "schema": "evidencegate.scan/v1", "subject": {"sha256": DEMO_DIGEST},
            "scanner": {"name": "synthetic-example-scanner", "version": "demo-1"},
            "scanned_at": iso(now - timedelta(minutes=10)), "status": "complete",
            "vulnerabilities": [],
        },
    }


def write_demo(directory: Path, now: datetime | None = None) -> dict:
    directory.mkdir(parents=True, exist_ok=True)
    bundle = demo_bundle(now)
    (directory / "artifact.txt").write_bytes(ARTIFACT)
    for name in ["provenance", "sbom", "scan", "policy"]:
        (directory / f"{name}.json").write_text(json.dumps(bundle[name], indent=2) + "\n", encoding="utf-8")
    (directory / "DATA_NOTICE.txt").write_text(
        "All demo inputs are synthetic. No software was built or scanned.\n"
        "Timestamps are generated for the demo, not measurements of an actual scan.\n", encoding="utf-8")
    return bundle
