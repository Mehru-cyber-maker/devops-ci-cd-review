"""Pure, offline checks. A passing report is not a signature verification."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import re
from typing import Any

from . import __version__

MAX_JSON_BYTES = 8 * 1024 * 1024
SEVERITIES = {"UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"}
LIMITATIONS = [
    "Checks consistency of supplied claims; does not verify signatures or producer identity.",
    "Does not run a vulnerability scanner, inspect artifact behavior, or prove software is safe.",
    "Timestamps, scan completeness, and source claims require a trusted collection process.",
    "PASS means supplied evidence satisfies this policy; it is not a security certification.",
]


class InputError(ValueError):
    """An invalid command, document, or policy."""


def sha256_string(value: Any) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[a-fA-F0-9]{64}", value):
        raise InputError("Expected a 64-character SHA-256 digest, without the sha256: prefix.")
    return value.lower()


def timestamp(value: Any) -> datetime:
    if not isinstance(value, str):
        raise InputError("Timestamp must be an ISO-8601 string with a timezone.")
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise InputError("Invalid ISO-8601 timestamp.") from exc
    if result.tzinfo is None:
        raise InputError("Timestamp must include a timezone.")
    try:
        return result.astimezone(timezone.utc)
    except (ValueError, OverflowError) as exc:
        raise InputError("Timestamp is outside the supported calendar range.") from exc


def iso(value: datetime) -> str:
    if value.tzinfo is None:
        raise InputError("Evaluation time must include a timezone.")
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _no_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise InputError(f"Duplicate JSON key: {key[:80]}")
        result[key] = value
    return result


def parse_json(raw: bytes) -> Any:
    if len(raw) > MAX_JSON_BYTES:
        raise InputError("JSON input exceeds the 8 MiB limit.")
    try:
        return json.loads(raw, object_pairs_hook=_no_duplicate_keys,
                          parse_constant=lambda x: (_ for _ in ()).throw(InputError("Non-finite JSON number.")))
    except InputError:
        raise
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise InputError("Input is not valid UTF-8 JSON.") from exc


def read_json(path: str | Path) -> Any:
    try:
        with Path(path).open("rb") as handle:
            return parse_json(handle.read(MAX_JSON_BYTES + 1))
    except OSError as exc:
        raise InputError(f"Cannot read {Path(path).name}: {exc.strerror}") from exc


def file_digest(path: str | Path) -> str:
    digest = hashlib.sha256()
    try:
        with Path(path).open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as exc:
        raise InputError(f"Cannot hash artifact: {exc.strerror}") from exc
    return digest.hexdigest()


@dataclass(frozen=True)
class Policy:
    allowed_builders: tuple[str, ...]
    source_uri: str
    source_commit: str
    max_scan_age_hours: int
    blocked_severities: tuple[str, ...]

    @classmethod
    def from_dict(cls, data: Any) -> "Policy":
        keys = {"schema_version", "allowed_builders", "expected_source", "max_scan_age_hours", "blocked_severities"}
        if not isinstance(data, dict) or set(data) != keys or type(data.get("schema_version")) is not int or data["schema_version"] != 1:
            raise InputError("Policy must use schema_version 1 and exactly the documented fields.")
        builders = data["allowed_builders"]
        if not isinstance(builders, list) or not builders or not all(isinstance(b, str) and b.strip() for b in builders):
            raise InputError("Policy needs a non-empty allowed_builders list.")
        source = data["expected_source"]
        if not isinstance(source, dict) or set(source) != {"uri", "commit"}:
            raise InputError("expected_source must contain uri and commit.")
        if not isinstance(source["uri"], str) or not source["uri"].strip():
            raise InputError("Source URI must be non-empty.")
        if not isinstance(source["commit"], str) or not re.fullmatch(r"[a-fA-F0-9]{40}|[a-fA-F0-9]{64}", source["commit"]):
            raise InputError("Source commit must be a full 40- or 64-character Git commit digest.")
        hours = data["max_scan_age_hours"]
        if type(hours) is not int or not 1 <= hours <= 8760:
            raise InputError("max_scan_age_hours must be an integer between 1 and 8760.")
        blocked = data["blocked_severities"]
        if not isinstance(blocked, list) or not blocked or not all(isinstance(s, str) and s in SEVERITIES for s in blocked):
            raise InputError("blocked_severities must be a non-empty list of documented uppercase severities.")
        return cls(tuple(builders), source["uri"], source["commit"].lower(), hours, tuple(blocked))


def _object(value: Any) -> bool:
    return isinstance(value, dict)


def _text(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _is_digest(value: Any) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[a-fA-F0-9]{64}", value) is not None


def _provenance_valid(data: Any) -> bool:
    if not _object(data) or data.get("_type") != "https://in-toto.io/Statement/v1" or data.get("predicateType") != "https://slsa.dev/provenance/v1":
        return False
    subjects = data.get("subject")
    if not isinstance(subjects, list) or not subjects:
        return False
    if not all(_object(s) and _text(s.get("name")) and _object(s.get("digest"))
               and _is_digest(s["digest"].get("sha256")) for s in subjects):
        return False
    predicate = data.get("predicate")
    if not _object(predicate):
        return False
    build = predicate.get("buildDefinition")
    run = predicate.get("runDetails")
    if not _object(build) or not _text(build.get("buildType")) or not _object(run):
        return False
    builder = run.get("builder")
    deps = build.get("resolvedDependencies")
    return (_object(builder) and _text(builder.get("id")) and isinstance(deps, list)
            and all(_object(d) and _text(d.get("uri")) and _object(d.get("digest")) for d in deps))


def _sbom_valid(data: Any) -> bool:
    if not _object(data) or data.get("bomFormat") != "CycloneDX" or not isinstance(data.get("specVersion"), str) or data["specVersion"] not in {"1.5", "1.6"}:
        return False
    if type(data.get("version")) is not int or data["version"] < 1:
        return False
    metadata = data.get("metadata")
    component = metadata.get("component") if _object(metadata) else None
    if not _object(component) or not _text(component.get("name")):
        return False
    hashes = component.get("hashes")
    if not isinstance(hashes, list) or not all(_object(h) and _text(h.get("alg")) and _text(h.get("content")) for h in hashes):
        return False
    components = data.get("components", [])
    return isinstance(components, list) and all(_object(c) and _text(c.get("name")) for c in components)


def _scan_valid(data: Any) -> bool:
    if not _object(data) or data.get("schema") != "evidencegate.scan/v1":
        return False
    subject, scanner = data.get("subject"), data.get("scanner")
    if not _object(subject) or not _is_digest(subject.get("sha256")):
        return False
    if not _object(scanner) or not _text(scanner.get("name")) or not _text(scanner.get("version")):
        return False
    if data.get("status") != "complete" or not isinstance(data.get("vulnerabilities"), list):
        return False
    # Check the date separately, so an invalid date has an explicit rule failure.
    for vulnerability in data["vulnerabilities"]:
        if not _object(vulnerability) or not _text(vulnerability.get("id")) or not _text(vulnerability.get("package")):
            return False
        if not isinstance(vulnerability.get("severity"), str) or vulnerability["severity"] not in SEVERITIES:
            return False
    return True


def evaluate(artifact_sha256: str, provenance: Any, sbom: Any, scan: Any,
             policy_data: Any, *, now: datetime | None = None) -> dict:
    """Compare supplied claims to an externally selected artifact and policy."""
    expected = sha256_string(artifact_sha256)
    policy = Policy.from_dict(policy_data)
    instant = now or datetime.now(timezone.utc)
    assessed_at = iso(instant)
    checks = []

    def add(code, category, passed, message, action):
        checks.append({"id": code, "category": category, "status": "pass" if passed else "fail",
                       "message": message, "action": "None required for this check." if passed else action})

    prov_ok = _provenance_valid(provenance)
    add("EG001", "Provenance", prov_ok,
        "Supported SLSA v1 statement structure." if prov_ok else "Missing or unsupported provenance structure.",
        "Supply a raw in-toto Statement v1 with SLSA provenance v1. Verify any signature using an external verifier.")
    subjects = [s["digest"]["sha256"].lower() for s in provenance["subject"]] if prov_ok else []
    add("EG002", "Artifact binding", expected in subjects,
        "Provenance includes the selected artifact." if expected in subjects else "Provenance is not bound to the selected artifact.",
        "Collect provenance for the selected release digest; do not relabel an older statement.")
    builder = provenance["predicate"]["runDetails"]["builder"]["id"] if prov_ok else None
    builder_ok = builder in policy.allowed_builders
    add("EG003", "Provenance", builder_ok,
        "Declared builder is allowlisted." if builder_ok else "Declared builder is absent or outside the allowlist.",
        "Use the approved build service and independently authenticate the statement's producer.")
    deps = provenance["predicate"]["buildDefinition"]["resolvedDependencies"] if prov_ok else []
    commits = [d["digest"].get("gitCommit") for d in deps if d["uri"] == policy.source_uri]
    source_ok = bool(commits) and all(isinstance(c, str) and c.lower() == policy.source_commit for c in commits)
    add("EG004", "Source", source_ok,
        "Declared source URI and commit match policy." if source_ok else "Expected source commit is missing, different, or conflicting.",
        "Rebuild from the independently selected repository and full commit; collect its resolved dependency record.")

    sbom_ok = _sbom_valid(sbom)
    add("EG005", "SBOM", sbom_ok,
        "Supported CycloneDX structure." if sbom_ok else "Missing or unsupported SBOM structure.",
        "Supply CycloneDX JSON 1.5 or 1.6 with metadata.component and a hashes list.")
    hashes = sbom["metadata"]["component"]["hashes"] if sbom_ok else []
    artifact_hashes = {h["content"].lower() for h in hashes if h["alg"] == "SHA-256"}
    sbom_bound = artifact_hashes == {expected}
    add("EG006", "Artifact binding", sbom_bound,
        "SBOM root component matches the selected artifact." if sbom_bound else "SBOM root artifact digest is missing, different, or conflicting.",
        "Generate the SBOM for this release and record its exact digest in metadata.component.hashes.")

    scan_ok = _scan_valid(scan)
    add("EG007", "Scan", scan_ok,
        "Supported scan record with declared complete status." if scan_ok else "Missing, partial, or malformed scan record.",
        "Supply evidencegate.scan/v1 with scanner version, complete status, and explicit vulnerabilities list.")
    scan_bound = scan_ok and scan["subject"]["sha256"].lower() == expected
    add("EG008", "Artifact binding", scan_bound,
        "Scan subject matches the selected artifact." if scan_bound else "Scan is not bound to the selected artifact.",
        "Scan the selected artifact. Preserve its digest in the collected scan record.")
    age_ok = False
    if scan_ok:
        try:
            age = instant - timestamp(scan.get("scanned_at"))
            age_ok = -timedelta(minutes=5) <= age <= timedelta(hours=policy.max_scan_age_hours)
        except InputError:
            pass
    add("EG009", "Freshness", age_ok,
        f"Declared scan time is within the {policy.max_scan_age_hours}-hour window." if age_ok else "Scan date is absent, invalid, too old, or more than five minutes in the future.",
        "Collect a fresh scan using a trustworthy clock and preserve the original scan timestamp.")
    vulnerabilities = scan["vulnerabilities"] if scan_ok else []
    blocked = [v for v in vulnerabilities if v["severity"] in policy.blocked_severities]
    vulnerability_ok = scan_ok and not blocked
    add("EG010", "Vulnerabilities", vulnerability_ok,
        "No supplied vulnerability violates the severity policy." if vulnerability_ok else
        f"{len(blocked)} supplied finding(s) violate policy." if scan_ok else "Cannot assess vulnerabilities from this scan record.",
        "Review the affected packages, remediate blocking findings, and collect new evidence. A missing record is not a clean scan.")

    failed = sum(c["status"] == "fail" for c in checks)
    return {"schema": "evidencegate.report/v1", "tool_version": __version__, "assessed_at": assessed_at,
            "artifact_sha256": expected, "decision": "BLOCK" if failed else "PASS",
            "summary": {"passed": len(checks)-failed, "failed": failed, "total": len(checks)},
            "checks": checks, "vulnerabilities": vulnerabilities,
            "policy": policy_data, "limitations": list(LIMITATIONS)}
