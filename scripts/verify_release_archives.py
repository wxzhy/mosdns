#!/usr/bin/env python3
"""Check the six Windows/Linux AMD64 archives and embedded Go build settings."""

import re
import subprocess
import tempfile
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
RELEASE_DIR = ROOT / "release"


def verify_archives():
    with tempfile.TemporaryDirectory() as temp_dir:
        for system in ("linux", "windows"):
            for amd64_level in ("v1", "v2", "v3"):
                suffix = "" if amd64_level == "v1" else f"-{amd64_level}"
                archive = RELEASE_DIR / f"mosdns-{system}-amd64{suffix}.zip"
                executable = "mosdns.exe" if system == "windows" else "mosdns"

                with zipfile.ZipFile(archive) as zf:
                    expected_members = {
                        executable, "README.md", "LICENSE", "config.yaml"
                    }
                    if set(zf.namelist()) != expected_members:
                        raise ValueError(f"{archive.name}: unexpected archive members")
                    data = zf.read(executable)
                    magic = b"MZ" if system == "windows" else b"\x7fELF"
                    if not data.startswith(magic):
                        raise ValueError(f"{archive.name}: incorrect executable format")

                extracted = Path(temp_dir) / executable
                extracted.write_bytes(data)
                result = subprocess.run(
                    ["go", "version", "-m", str(extracted)],
                    check=True, text=True, capture_output=True,
                )
                for setting in (
                    "GOARCH=amd64",
                    f"GOOS={system}",
                    f"GOAMD64={amd64_level}",
                ):
                    if re.search(r"(?m)^\s*build\s+" + re.escape(setting) + r"$",
                                 result.stdout) is None:
                        raise ValueError(f"{archive.name}: expected {setting}")

                print(f"OK {archive.name}: {system}/amd64 {amd64_level} "
                      f"({len(data):,} bytes)")


if __name__ == "__main__":
    verify_archives()
