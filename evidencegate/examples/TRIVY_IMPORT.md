# Import a real Trivy scan

This optional adapter requires a separately installed Trivy. It does not run Trivy or authenticate its output.

1. Select the exact OCI **manifest digest** you intend to release. Do not use a container configuration `ImageID` or the hash of a tar archive.
2. Run a successful vulnerability scan of that digest with `--scanners vuln --format json`.
3. Retain the actual Trivy version and completion timestamp in trusted job metadata.
4. Import the report:

```bash
python -m evidencegate import-trivy --input trivy.json --sha256 YOUR_64_CHARACTER_MANIFEST_DIGEST --scanned-at ACTUAL_SCAN_TIME_WITH_TIMEZONE --scanner-version ACTUAL_TRIVY_VERSION --confirm-vulnerability-scan --output outputs/scan.json
```

Replace the uppercase placeholders. The digest must already appear in `Metadata.RepoDigests`. The adapter rejects `ImageID` as a substitute and rejects reports without supported package results.

Trivy can omit a vulnerability field for a clean result. Its JSON does not independently establish the original scanner flags or successful collection. The explicit confirmation is your assertion that a complete vulnerability scan ran; preserve its command and exit status.

The normalized report carries the declared timestamp and version. It does not attest their truth. Use it with provenance and an SBOM bound to the same manifest digest and with a policy selected independently of these records.
