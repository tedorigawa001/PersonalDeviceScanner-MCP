#!/usr/bin/env python3
"""Validate the generated BOM against official local schemas and evidence hashes."""
import argparse
import hashlib
import json
from pathlib import Path

from jsonschema import Draft7Validator
from referencing import Registry, Resource

ROOT = Path(__file__).resolve().parents[1]


def validate(root, schema_dir):
    registry = Registry()
    for path in schema_dir.glob("*.json"):
        schema = json.loads(path.read_text())
        Draft7Validator.check_schema(schema)
        resource = Resource.from_contents(schema)
        for uri in {schema.get("$id", ""), "http://cyclonedx.org/schema/" + path.name,
                    "https://cyclonedx.org/schema/" + path.name} - {""}:
            registry = registry.with_resource(uri, resource)
    schema = json.loads((schema_dir / "bom-1.6.schema.json").read_text())
    bom = json.loads((root / "sbom/python-agent.cdx.json").read_text())
    Draft7Validator(schema, registry=registry).validate(bom)
    components = bom["components"]
    by_name = {c["name"]: c for c in components}
    assert len(by_name) == len(components), "Duplicate components"
    refs = {c["bom-ref"] for c in components} | {bom["metadata"]["component"]["bom-ref"]}
    assert len(refs) == len(components) + 1, "Duplicate refs"
    assert {d["ref"] for d in bom["dependencies"]} == refs, "Incomplete dependency graph"
    assert all(set(d["dependsOn"]) <= refs for d in bom["dependencies"]), "Dangling edge"
    manifest = json.loads((root / "third_party/license-manifest.json").read_text())
    assert not manifest["unresolved"], "Unresolved Python license evidence"
    assert {c["name"] for c in manifest["components"]} == set(by_name), "Manifest/BOM mismatch"
    for entry in manifest["components"]:
        component = by_name[entry["name"]]
        assert entry["version"] == component["version"], "Version mismatch"
        assert entry["license_expression"] == component["licenses"][0]["expression"], "License mismatch"
        assert entry["notices"], "Original notice missing"
        for evidence in [{"path": entry["metadata_path"], "sha256": entry["metadata_sha256"]}, *entry["notices"]]:
            path = (root / evidence["path"]).resolve()
            assert path.is_relative_to(root.resolve()), "Evidence path escapes root"
            assert hashlib.sha256(path.read_bytes()).hexdigest() == evidence["sha256"], "Evidence changed"
    artifacts = json.loads((root / "sbom/reference-artifacts.json").read_text())["artifacts"]
    pins = {}
    for line in (root / "requirements-agent.lock").read_text().splitlines():
        if line and not line.startswith("#"):
            pin, *hashes = line.split()
            name, version = pin.split("==", 1)
            pins[name] = (version, hashes)
    assert set(pins) == set(by_name), "Lock/BOM mismatch"
    for name, component in by_name.items():
        assert pins[name][0] == component["version"], "Lock version mismatch"
    if artifacts:
        assert {a["name"] for a in artifacts} == set(by_name), "Artifact set incomplete"
        for artifact in artifacts:
            component = by_name[artifact["name"]]
            assert component["hashes"] == [{"alg": "SHA-256", "content": artifact["sha256"]}], "Wheel hash mismatch"
            assert pins[artifact["name"]][1] == ["--hash=sha256:" + artifact["sha256"]], "Lock hash mismatch"
    assert bom["compositions"][0]["aggregate"] == "incomplete", "Do not claim full native coverage"
    return len(components), sum(len(e["notices"]) for e in manifest["components"])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--schema-dir", type=Path, required=True)
    args = parser.parse_args()
    count, notices = validate(args.root, args.schema_dir)
    print(f"CycloneDX 1.6 schema, dependency graph, lock and evidence verified: {count} packages, {notices} original notices")


if __name__ == "__main__":
    main()
