#!/usr/bin/env python3
"""Check that built wheel/sdist preserve all notice bytes and sdist SBOMs."""
import argparse
import hashlib
import json
import tarfile
import tomllib
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def verify(directory, root=ROOT):
    project = tomllib.loads((root / "pyproject.toml").read_text())["project"]
    source_prefix = project["name"].replace("-", "_") + "-" + project["version"] + "/"
    manifest = json.loads((root / "third_party/license-manifest.json").read_text())
    expected = {"LICENSE": (root / "LICENSE").read_bytes(),
                "THIRD_PARTY_NOTICES.md": (root / "THIRD_PARTY_NOTICES.md").read_bytes()}
    for component in manifest["components"]:
        for notice in component["notices"]:
            expected[notice["path"]] = (root / notice["path"]).read_bytes()
    wheels, sources = sorted(directory.glob("*.whl")), sorted(directory.glob("*.tar.gz"))
    assert len(wheels) == len(sources) == 1, "Use a clean output folder with one wheel and sdist"
    with zipfile.ZipFile(wheels[0]) as archive:
        prefixes = [n.rsplit("/", 1)[0] + "/licenses/" for n in archive.namelist()
                    if n.endswith(".dist-info/METADATA")]
        assert len(prefixes) == 1, "Ambiguous wheel metadata"
        for relative, data in expected.items():
            assert archive.read(prefixes[0] + relative) == data, f"Wheel notice changed or missing: {relative}"
        assert not any(n.endswith(('.so', '.dylib', '.dll', '.exe')) for n in archive.namelist()), "Unexpected binary bundle"
    with tarfile.open(sources[0], "r:gz") as archive:
        for relative in [*expected, "sbom/python-agent.cdx.json", "sbom/reference-artifacts.json",
                         "sbom/external-integrations.json", "requirements-agent.lock",
                         "scripts/generate_compliance.py", "scripts/validate_compliance.py",
                         "scripts/verify_distribution.py", "docs/license-recommendation.md", "docs/compliance.md"]:
            stream = archive.extractfile(source_prefix + relative)
            assert stream is not None and stream.read() == (root / relative).read_bytes(), f"sdist missing/changed: {relative}"
    checksums = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in [*wheels, *sources]}
    print(json.dumps({"status": "verified", "notice_files_per_distribution": len(expected), "artifacts_sha256": checksums}, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    verify(parser.parse_args().directory)
