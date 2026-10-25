# EvidenceGate research paper

**EvidenceGate: Checking Security Evidence Against CI/CD Release Artifacts**

A separate research manuscript reporting measurements from the existing prototype. All earlier repository files, including the literature review and tool source, are unchanged.

## Download

- [Read the PDF paper](EvidenceGate_Research_Paper.pdf)
- [Download the editable Word paper](EvidenceGate_Research_Paper.docx)
- [Read the manuscript on GitHub](EvidenceGate_Research_Paper.md)
- [Download the paper, data, figures, and tool source](EvidenceGate_Research_Package.zip)

On GitHub, open a PDF, Word, or ZIP file and select **Download raw file**.

## Included results

| Evaluation | Observed result |
|:--|:--|
| Functional fixtures | Full checker blocked 22/22 faulty cases; ablation blocked 17/22 |
| Factorial combinations | Full checker blocked 63/63 faulty combinations; ablation blocked 56/63 |
| Existing software tests | 31 passed; no failures, errors, or skips |
| Browser checks | 10 passed, including downloads, file hashing, and mobile layout |
| Timing | 400 raw observations at four input sizes |

The paper contains **six figures and seven comparison tables**. Figures are supplied as PNG, SVG, and vector PDF; tables are editable CSV files.

Results are from controlled synthetic cases. They do not establish real-world attack detection, product superiority, signature verification, or publication novelty. Two residual-trust demonstrations show why consistent false claims can still pass.

## Inspect the evidence

- [Raw decisions and metrics](results/)
- [Software-test log](results/unittest.log)
- [Browser results](results/browser_tests.json)
- [Raw timing observations](results/timing_raw.csv)
- [Environment and evaluated source hashes](results/environment.json)
- [Figures](figures/) and [comparison tables](tables/)

The manuscript uses short paragraphs and retains the earlier preference to omit citation markers and a bibliography. Add verified prior-work references and target-venue formatting before submission.

## Reproduce

Use Python 3.10+ with the adjacent `evidencegate/` source folder. The downloadable package includes both folders. The tested environment used Python 3.12.14; timing will vary by machine.

From this research folder:

```bash
python -m pip install -r requirements-research.txt
python scripts/run_evaluation.py
python scripts/make_figures.py
python scripts/write_paper.py
python scripts/build_documents.py
python scripts/verify_results.py
```

Document generation also needs the `pandoc` executable and DejaVu fonts. On Debian/Ubuntu these are available as `pandoc` and `fonts-dejavu-core`.

To rerun browser checks, install Playwright and Chromium, then run `python scripts/test_dashboard.py`. The checked-in script uses `/usr/bin/chromium`; adjust that path for your system. Run browser checks before generating Figure 6 if you want fresh browser observations; otherwise the saved browser results are used.

The fixed policy-assessment time is a synthetic experiment setting, not a suggested production clock override. Regenerated timings and timestamps will differ. Rebuild the manuscript and figures after changing saved measurements.
