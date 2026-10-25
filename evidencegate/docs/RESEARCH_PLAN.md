# Using EvidenceGate for a research paper

## Possible title

**Artifact-Bound Security Evidence Checks in CI/CD: Design and Evaluation of EvidenceGate**

The current tool is an engineering prototype. Its novelty has not been established. Compare its scope with existing supply-chain verification and admission-policy tools before selecting a research contribution.

## Problem and proposed contribution

Separate security reports can appear acceptable while referring to different releases. EvidenceGate tests whether provenance, an SBOM, and a scan are consistent with a selected artifact and policy.

A defensible contribution could be a documented consistency-checking method, a reproducible fault dataset, and an empirical comparison of failure detection and integration effort. The current synthetic demonstration is only the starting point.

## Research questions

1. Which evidence mismatches does artifact binding detect beyond independent document checks?
2. How often do missing, stale, or inconsistent records occur in a controlled collection of real builds?
3. What assessment overhead and developer effort does the tool add?
4. Which attacks remain invisible when all supplied claims are mutually consistent?

## What has actually been evaluated

The included benchmark runs 27 constructed cases: five valid cases and 22 known faults. It compares presence checks, an ablation without artifact binding, and the full checker. Inputs, labels, decisions, and computed summaries are saved.

These fixtures were not collected from real organizations or attacks. The demo scanner does not scan anything. The Trivy adapter is covered by contract fixtures; an installed Trivy/container pipeline has not been evaluated here.

Run this from the project folder to reproduce the checked-in dataset and decisions:

```bash
python -m evidencegate benchmark --output-dir outputs/reproduction --seed 7 --repeats 10 --at 2026-10-25T09:00:00Z
```

Runtime measurements will vary by machine. The fixed timestamp affects only the synthetic experiment; do not override the clock in a live release gate to bypass freshness checks.

## Stronger evaluation to perform

| Step | Method | Evidence to retain |
|:--|:--|:--|
| Collect real builds | Use a small container application, pinned commits, and repeated releases | Artifact digests, versions, collection commands, build logs |
| Collect authentic evidence | Verify provenance externally; generate SBOM and scan for the exact manifest | Original records and external verification outcome |
| Create controlled faults | Reuse an earlier report, remove a required record, or vary source/age | Mutation description and independently assigned label |
| Include difficult controls | Valid multi-subject statements, benign changes, and forged-but-consistent claims | Expected behavior and known observability limits |
| Compare fairly | Run an existing verifier/policy engine and both included baselines on equivalent inputs | Configuration, decisions, and unsupported-input handling |
| Measure overhead | Repeat assessments; separately time parsing, rule evaluation, and full collection | Raw times, hardware, versions, repetitions |
| Test usability | Have permitted volunteers diagnose failed checks using a fixed task | Time, errors, feedback, and consent where required |

Do not treat slightly modified copies of one release as independent projects. Hold back some releases and fault combinations during development. Keep the evaluator and labels independent where possible.

## Metrics

Use a faulty release as the positive class. A true block rejects a faulty case; a false accept allows it. A false block rejects a valid case; a true accept allows it.

- Precision = true blocks / all blocks.
- Recall = true blocks / all faulty cases.
- F1 = harmonic mean of precision and recall.
- Report false accepts and false blocks by fault category.
- Report timing distributions and input sizes, not one favorable timing.

The included timing covers only the full in-memory evaluator. It excludes input parsing, artifact hashing, scanning, external verification, and baseline timing. It is not end-to-end pipeline latency.

The labels follow the synthetic construction, so high scores on these fixtures are expected. Do not describe them as evidence of general attack detection. Investigate naturally occurring failures and out-of-scope controls separately.

## Paper outline

1. **Introduction:** Evidence mismatch problem and research questions.
2. **Related work:** Existing artifact verification, SBOM, vulnerability gating, and policy systems.
3. **Threat model:** Trusted inputs, attacker capabilities, and observable failures.
4. **Method:** Artifact binding, policy rules, and report generation.
5. **Evaluation:** Dataset, labels, baselines, metrics, and reproducible commands.
6. **Results:** Only measurements actually collected; include failures and limitations.
7. **Discussion:** Integration effort, generalizability, and remaining trust assumptions.
8. **Conclusion:** Supported findings and future work.

Keep this new implementation study separate from the existing review paper. Publication claims require a fresh literature comparison and actual empirical evidence; the current prototype alone does not establish a PhD-level contribution.
