#!/usr/bin/env python3
"""Build a Python runtime SBOM and preserve actual installed license evidence.

Run with the release venv's Python. packaging is tooling, not an app dependency;
pip's vendored copy is used if no standalone packaging is installed.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.metadata as metadata
import json
import platform
import re
import sys
import tomllib
import uuid
import zipfile
from collections import defaultdict
from pathlib import Path, PurePosixPath

try:
    from packaging.licenses import canonicalize_license_expression
    from packaging.requirements import Requirement
    from packaging.utils import canonicalize_name
except ImportError:
    from pip._vendor.packaging.licenses import canonicalize_license_expression
    from pip._vendor.packaging.requirements import Requirement
    from pip._vendor.packaging.utils import canonicalize_name

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_URL = "http://cyclonedx.org/schema/bom-1.6.schema.json"


def encode_json(value):
    return (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode()


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def active_requirement(text, extras):
    requirement = Requirement(text)
    if requirement.marker and not any(requirement.marker.evaluate({"extra": e}) for e in {"", *extras}):
        return None
    if requirement.url:
        raise ValueError(f"Direct URL dependency requires explicit provenance review: {requirement.name}")
    return requirement


def resolve_graph(requirements, get_distribution=metadata.distribution):
    """Follow marker/extra-aware dependencies, failing on missing/conflicting versions."""
    distributions, edges = {}, defaultdict(set)
    requested_extras, processed = defaultdict(set), {}
    pending = [("project", Requirement(r)) for r in requirements]
    while pending:
        parent, requirement = pending.pop()
        name = canonicalize_name(requirement.name)
        dist = distributions.setdefault(name, get_distribution(name))
        if not requirement.specifier.contains(dist.version, prereleases=True):
            raise ValueError(f"Installed {name}=={dist.version} does not satisfy {requirement}")
        edges[parent].add(name)
        requested_extras[name].update(requirement.extras)
        extras = frozenset(requested_extras[name])
        if processed.get(name) == extras:
            continue
        processed[name] = extras
        edges.setdefault(name, set())
        for text in dist.requires or []:
            dependency = active_requirement(text, extras)
            if dependency:
                pending.append((name, dependency))
    return distributions, edges


def wheel_inventory(directory):
    wheels = {}
    if not directory:
        return wheels
    for path in sorted(directory.glob("*.whl")):
        with zipfile.ZipFile(path) as archive:
            members = [n for n in archive.namelist() if n.endswith(".dist-info/METADATA")]
            if len(members) != 1:
                raise ValueError(f"Unexpected wheel metadata: {path.name}")
            from email.parser import BytesParser
            message = BytesParser().parsebytes(archive.read(members[0]))
            key = (canonicalize_name(message["Name"]), message["Version"])
        if key in wheels:
            raise ValueError(f"Multiple wheels for {key}; use one target platform per snapshot")
        wheels[key] = {"filename": path.name, "sha256": sha256(path.read_bytes()),
                       "path": path}
    return wheels


def collect(project_path=ROOT / "pyproject.toml", wheels_dir=None):
    project = tomllib.loads(project_path.read_text())["project"]
    roots = list(project.get("dependencies", [])) + project.get("optional-dependencies", {}).get("agent", [])
    roots = [str(r) for text in roots if (r := active_requirement(text, {"agent"}))]
    distributions, edges = resolve_graph(roots)
    wheels = wheel_inventory(wheels_dir)
    output, components, manifest, unresolved = {}, [], [], []
    environment = {"python": platform.python_version(), "implementation": platform.python_implementation(),
                   "os": platform.system(), "architecture": platform.machine(),
                   "marker_environment": "evaluated for this interpreter only"}
    reference = lambda name, version: f"pkg:pypi/{canonicalize_name(name)}@{version}"
    refs = {name: reference(name, dist.version) for name, dist in distributions.items()}
    root_ref = reference(project["name"], project["version"])
    lines = ["# Third-party notices — Python agent profile", "", "Generated from installed distribution metadata; preserve the linked original texts.",
             "These declarations apply to third-party packages only, not to the project's own code.",
             "Scope: Python dependencies for the agent extra on the recorded platform. Native vendored libraries require separate review.",
             "Wazuh, osquery, ClamAV, the Python interpreter and build/install tools are not bundled in this scope.", "",
             "Environment: " + ", ".join(f"{k}={v}" for k, v in environment.items()), "",
             "| Package | Version | Declared license | Original notices |", "|---|---|---|---|"]
    pinned, artifacts = [], []
    for name, dist in sorted(distributions.items()):
        raw_metadata = dist.read_text("METADATA")
        if raw_metadata is None:
            raise ValueError(f"Missing METADATA for {name}")
        expression = dist.metadata.get("License-Expression")
        evidence = "License-Expression"
        if not expression:
            legacy = dist.metadata.get("License", "").strip()
            # Do not guess SPDX IDs from prose or classifier names.
            if legacy in {"MIT", "BSD-3-Clause", "MPL-2.0", "Apache-2.0"}:
                expression, evidence = legacy, "legacy License field (exact identifier)"
            else:
                expression, evidence = None, "not determined"
                unresolved.append(f"{name}: license expression unknown")
        if expression:
            expression = canonicalize_license_expression(expression)
        base = f"third_party/licenses/{name}/{dist.version}"
        copied = []
        for entry in sorted(dist.files or [], key=str):
            parts = PurePosixPath(str(entry)).parts
            lower = [p.lower() for p in parts]
            in_license_folder = "licenses" in lower and any(p.endswith(".dist-info") for p in parts)
            basename = parts[-1].lower() if parts else ""
            named_notice = bool(re.match(r"^(licen[cs]e|copying|notice|copyright|authors)(\.|$)", basename))
            if not (in_license_folder or named_notice):
                continue
            if ".." in parts or PurePosixPath(str(entry)).is_absolute():
                raise ValueError(f"Unsafe license path in {name}")
            source = Path(dist.locate_file(entry))
            if not source.is_file():
                raise ValueError(f"Missing declared license file in {name}: {entry}")
            destination = f"{base}/{entry}"
            data = source.read_bytes()
            output[destination] = data
            copied.append({"path": destination, "source_path": str(entry), "sha256": sha256(data)})
        if not copied:
            unresolved.append(f"{name}: no original license/notice file found")
        metadata_path = f"third_party/metadata/{name}-{dist.version}.METADATA"
        output[metadata_path] = raw_metadata.encode()
        props = [{"name": "pc-scanner:license-evidence", "value": evidence},
                 {"name": "pc-scanner:installed-metadata-sha256", "value": sha256(output[metadata_path])}]
        component = {"type": "library", "bom-ref": refs[name], "name": name, "version": dist.version,
                     "purl": refs[name], "scope": "required", "properties": props,
                     "externalReferences": [{"type": "distribution", "url": f"https://pypi.org/project/{name}/{dist.version}/"}]}
        if expression:
            component["licenses"] = [{"expression": expression}]
        wheel = wheels.get((name, dist.version))
        if wheels_dir and not wheel:
            raise ValueError(f"Missing wheel for {name}=={dist.version}")
        lock_line = f"{name}=={dist.version}"
        if wheel:
            with zipfile.ZipFile(wheel["path"]) as archive:
                for notice in copied:
                    try:
                        wheel_text = archive.read(notice["source_path"])
                    except KeyError:
                        raise ValueError(f"Reference wheel missing installed notice: {name}") from None
                    if sha256(wheel_text) != notice["sha256"]:
                        raise ValueError(f"Reference wheel license differs from installed evidence: {name}")
            # This is a reference distribution artifact, not proof of the installed wheel's origin.
            component["hashes"] = [{"alg": "SHA-256", "content": wheel["sha256"]}]
            props.append({"name": "pc-scanner:reference-wheel", "value": wheel["filename"]})
            props.append({"name": "pc-scanner:artifact-provenance", "value": "downloaded reference wheel; installed origin not attested"})
            props.append({"name": "pc-scanner:license-match", "value": "original notices match reference wheel bytes"})
            artifacts.append({"name": name, "version": dist.version, "filename": wheel["filename"],
                              "sha256": wheel["sha256"], "source": f"https://pypi.org/project/{name}/{dist.version}/"})
            lock_line += f" --hash=sha256:{wheel['sha256']}"
        pinned.append(lock_line)
        components.append(component)
        manifest.append({"name": name, "version": dist.version, "license_expression": expression,
                         "license_evidence": evidence, "metadata_path": metadata_path,
                         "metadata_sha256": sha256(output[metadata_path]), "notices": copied})
        links = "<br>".join(f"[{Path(f['path']).name}]({f['path']})" for f in copied) or "MISSING — review required"
        lines.append(f"| [{name}](https://pypi.org/project/{name}/{dist.version}/) | {dist.version} | {expression or 'UNKNOWN'} | {links} |")
    if "certifi" in distributions:
        certifi_version = distributions["certifi"].version
        lines.extend(["", "## MPL-2.0 source availability", "",
                      f"certifi {certifi_version}: corresponding upstream Source Distribution is available at "
                      f"[PyPI release files](https://pypi.org/project/certifi/{certifi_version}/#files).",
                      "If distributing a modified copy, provide the corresponding modified MPL-covered source as well.",
                      "Verify source availability at release time and retain this notice with the distribution."])
    root_component = {"type": "application", "bom-ref": root_ref, "name": project["name"],
                      "version": project["version"], "purl": root_ref,
                      "properties": [{"name": "pc-scanner:own-license-status", "value": "MIT proposed, not granted"}]}
    if isinstance(project.get("license"), str):
        root_component["licenses"] = [{"expression": project["license"]}]
        root_component["properties"][0]["value"] = "declared in pyproject.toml"
    bom = {"$schema": SCHEMA_URL, "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
           "metadata": {"component": root_component, "properties": [
               {"name": "pc-scanner:profile", "value": "agent"},
               {"name": "pc-scanner:scope", "value": "Python runtime dependency graph; native libraries, external tools and interpreter excluded"},
               {"name": "pc-scanner:environment", "value": json.dumps(environment, sort_keys=True)},
               {"name": "pc-scanner:generator", "value": "scripts/generate_compliance.py"}]},
           "components": components,
           "compositions": [{"aggregate": "incomplete", "assemblies": [root_ref]}],
           "dependencies": [{"ref": root_ref if name == "project" else refs[name],
                             "dependsOn": sorted(refs[child] for child in children)}
                            for name, children in sorted(edges.items())]}
    bom["serialNumber"] = "urn:uuid:" + str(uuid.uuid5(uuid.NAMESPACE_URL, sha256(encode_json(bom))))
    output["sbom/python-agent.cdx.json"] = encode_json(bom)
    output["third_party/license-manifest.json"] = encode_json({"environment": environment, "components": manifest,
                                                              "unresolved": unresolved})
    output["sbom/reference-artifacts.json"] = encode_json({"environment": environment, "artifacts": artifacts,
        "note": "Reference wheels; not an attestation of installed provenance or a complete native-library SBOM"})
    output["THIRD_PARTY_NOTICES.md"] = ("\n".join(lines) + "\n").encode()
    output["requirements-agent.lock"] = ("# agent profile; platform-specific snapshot, not a universal lock\n"
        + "# Python/OS: " + json.dumps(environment, sort_keys=True) + "\n"
        + ("# Reference wheel hashes included; use --require-hashes\n" if wheels_dir else "# Versions only; wheel hashes not supplied\n")
        + "\n".join(pinned) + "\n").encode()
    return output, unresolved


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT)
    parser.add_argument("--wheels-dir", type=Path)
    parser.add_argument("--check", action="store_true", help="Compare without writing")
    args = parser.parse_args()
    try:
        outputs, unresolved = collect(wheels_dir=args.wheels_dir)
        differences = []
        for relative, data in outputs.items():
            path = args.output / relative
            if args.check:
                if not path.is_file() or path.read_bytes() != data:
                    differences.append(relative)
            else:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data)
        if differences or unresolved:
            print(json.dumps({"different_files": differences, "unresolved": unresolved}, indent=2))
            return 1
        print(f"{'Verified' if args.check else 'Generated'} {len(outputs)} compliance files; no missing Python license evidence")
        return 0
    except (ValueError, OSError, metadata.PackageNotFoundError) as exc:
        print(f"Compliance generation failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
