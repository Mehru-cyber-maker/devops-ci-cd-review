"""Package the new manuscript and adjacent unchanged tool source."""

import hashlib
from pathlib import Path
import subprocess
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo

ROOT = Path(__file__).resolve().parents[1]
REPO = ROOT.parent


def main():
    archive_path = ROOT/"EvidenceGate_Research_Package.zip"
    research_files = [p for p in sorted(ROOT.rglob("*")) if p.is_file() and p != archive_path
                      and not any(part in {".build","__pycache__",".venv"} for part in p.relative_to(ROOT).parts)]
    tool_paths = subprocess.check_output(["git","ls-files","-z","--","evidencegate"],cwd=REPO).decode().split("\0")
    tool_files = [REPO/name for name in tool_paths if name and not name.endswith(".zip")]
    manifest = []
    with ZipFile(archive_path,"w",ZIP_DEFLATED) as archive:
        for path in research_files+tool_files:
            name = path.relative_to(REPO).as_posix()
            data = path.read_bytes()
            info = ZipInfo(name,date_time=(2020,1,1,0,0,0))
            info.compress_type = ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            archive.writestr(info,data)
            manifest.append(hashlib.sha256(data).hexdigest()+"  "+name)
        info=ZipInfo("SHA256SUMS.txt",date_time=(2020,1,1,0,0,0))
        info.compress_type=ZIP_DEFLATED
        archive.writestr(info,"\n".join(manifest)+"\n")
    print(f"Packaged {len(research_files)} research files and {len(tool_files)} unchanged tool files.")


if __name__ == "__main__":
    main()
