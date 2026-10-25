"""Create a standalone source ZIP without papers, caches, or local outputs."""

import hashlib
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo

ROOT = Path(__file__).resolve().parents[1]
EXCLUDE = {"outputs", ".venv", "__pycache__", "build", "dist", ".git"}
SUFFIXES = {".py", ".md", ".json", ".csv", ".txt", ".toml", ".yml", ".png", ".html", ".css", ".js", ".svg"}


def main():
    files = [p for p in sorted(ROOT.rglob("*")) if p.is_file()
             and not any(part in EXCLUDE or part.endswith(".egg-info") for part in p.relative_to(ROOT).parts)
             and (p.suffix in SUFFIXES or p.name == ".gitignore")]
    output = ROOT/"EvidenceGate_Tool.zip"
    manifest = []
    with ZipFile(output, "w", ZIP_DEFLATED) as archive:
        for path in files:
            relative = "evidencegate/"+path.relative_to(ROOT).as_posix()
            data = path.read_bytes()
            info = ZipInfo(relative, date_time=(2020, 1, 1, 0, 0, 0))
            info.compress_type = ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            archive.writestr(info, data)
            manifest.append(hashlib.sha256(data).hexdigest()+"  "+relative)
        info = ZipInfo("evidencegate/SHA256SUMS.txt", date_time=(2020, 1, 1, 0, 0, 0))
        info.compress_type = ZIP_DEFLATED
        archive.writestr(info, "\n".join(manifest)+"\n")
    print(f"Packaged {len(files)} files: {output.name}")


if __name__ == "__main__":
    main()
