"""Import native Trivy JSON without confusing OCI image/config digests."""

from .core import InputError, SEVERITIES, sha256_string, timestamp, iso


def import_trivy(data, digest: str, scanned_at: str, scanner_version: str) -> dict:
    """Caller must independently confirm vulnerability scanning was enabled."""
    digest = sha256_string(digest)
    date = iso(timestamp(scanned_at))
    if not isinstance(scanner_version, str) or not scanner_version.strip():
        raise InputError("A recorded Trivy version is required.")
    if not isinstance(data, dict) or type(data.get("SchemaVersion")) is not int or data["SchemaVersion"] != 2:
        raise InputError("Expected Trivy JSON SchemaVersion 2.")
    metadata = data.get("Metadata")
    repo_digests = metadata.get("RepoDigests") if isinstance(metadata, dict) else None
    if not isinstance(repo_digests, list) or not all(isinstance(d, str) for d in repo_digests):
        raise InputError("Trivy Metadata.RepoDigests is required; ImageID is not a manifest digest.")
    if not any(d.endswith("@sha256:" + digest) for d in repo_digests):
        raise InputError("Selected OCI manifest digest is not present in Trivy Metadata.RepoDigests.")
    results = data.get("Results")
    if not isinstance(results, list) or not all(isinstance(r, dict) for r in results):
        raise InputError("Trivy Results must be a list of objects.")
    package_results = [r for r in results if r.get("Class") in ("os-pkgs", "lang-pkgs")]
    if not package_results:
        raise InputError("No supported package scan results; completeness cannot be inferred.")
    vulnerabilities = []
    for result in package_results:
        entries = result.get("Vulnerabilities")
        # Trivy omits this field for a clean result. The explicit CLI confirmation is required.
        if entries is None:
            entries = []
        if not isinstance(entries, list):
            raise InputError("Trivy Vulnerabilities must be an array or null.")
        for entry in entries:
            if not isinstance(entry, dict):
                raise InputError("Malformed Trivy vulnerability entry.")
            identifier, package, severity = entry.get("VulnerabilityID"), entry.get("PkgName"), entry.get("Severity")
            if not isinstance(identifier, str) or not identifier.strip() or not isinstance(package, str) or not package.strip():
                raise InputError("Trivy finding needs VulnerabilityID and PkgName.")
            if not isinstance(severity, str) or severity not in SEVERITIES:
                raise InputError("Unsupported or absent Trivy severity.")
            vulnerabilities.append({"id": identifier, "package": package, "severity": severity})
    return {"schema": "evidencegate.scan/v1", "subject": {"sha256": digest},
            "scanner": {"name": "Trivy", "version": scanner_version},
            "scanned_at": date, "status": "complete", "vulnerabilities": vulnerabilities}
