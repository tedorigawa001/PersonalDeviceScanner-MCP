import ast
import importlib.metadata as metadata
import importlib.util
import io
import json
import sys
import tempfile
import tomllib
import unittest
from contextlib import redirect_stdout
from itertools import chain
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from scripts.generate_compliance import (ROOT, Requirement, active_requirement, canonicalize_name, main,
                                         resolve_graph)


class DependencyGraphTests(unittest.TestCase):
    def test_transitive_extras_are_preserved(self):
        packages = {
            "direct": SimpleNamespace(version="1", requires=["optional[crypto]>=1"]),
            "optional": SimpleNamespace(version="1", requires=["native>=1; extra == 'crypto'", "absent; extra == 'test'"]),
            "native": SimpleNamespace(version="1", requires=[]),
        }
        graph, edges = resolve_graph(["direct>=1"], packages.__getitem__)
        self.assertEqual(set(graph), {"direct", "optional", "native"})
        self.assertEqual(edges["optional"], {"native"})

    def test_revisited_extra_adds_dependencies(self):
        packages = {
            "shared": SimpleNamespace(version="1", requires=["native; extra == 'crypto'"]),
            "native": SimpleNamespace(version="1", requires=[]),
        }
        graph, _ = resolve_graph(["shared[crypto]", "shared"], packages.__getitem__)
        self.assertIn("native", graph)

    def test_conflicting_installed_version_fails(self):
        with self.assertRaisesRegex(ValueError, "does not satisfy"):
            resolve_graph(["package>=2"], lambda name: SimpleNamespace(version="1", requires=[]))

    def test_inactive_platform_marker_and_direct_url(self):
        self.assertIsNone(active_requirement("absent; python_version < '1'", set()))
        with self.assertRaisesRegex(ValueError, "provenance review"):
            active_requirement("package @ https://example.org/package.whl", set())


class DeclaredDependencyTests(unittest.TestCase):
    def test_direct_imports_are_declared(self):
        # A package the code imports must be declared, not just arrive through another one,
        # so the SBOM records it as a direct dependency.
        project = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]
        declared = {canonicalize_name(Requirement(text).name) for text in
                    [*project.get("dependencies", []), *chain(*project.get("optional-dependencies", {}).values())]}
        imported = set()
        for source in (ROOT / "pc_scanner").glob("*.py"):
            for node in ast.walk(ast.parse(source.read_text(encoding="utf-8"))):
                if isinstance(node, ast.Import):
                    imported.update(alias.name.split(".")[0] for alias in node.names)
                elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                    imported.add(node.module.split(".")[0])
        third_party = sorted(imported - set(sys.stdlib_module_names) - {"pc_scanner"})
        self.assertTrue(third_party)
        for module in third_party:
            with self.subTest(module=module):
                # A module maps to its distribution only when installed; the declared name covers the rest.
                names = metadata.packages_distributions().get(module, [module])
                self.assertTrue({canonicalize_name(name) for name in names} & declared,
                                f"{module} is imported but not declared in pyproject.toml")


class SecurityFloorTests(unittest.TestCase):
    def test_certifi_floor_rejects_compromised_root_bundle(self):
        project = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]
        floors = [Requirement(text) for text in project["optional-dependencies"]["agent"]
                  if Requirement(text).name == "certifi"]
        self.assertEqual(len(floors), 1)
        self.assertIsNone(floors[0].marker)
        self.assertFalse(floors[0].specifier.contains("2026.7.22"))
        self.assertFalse(floors[0].specifier.contains("2026.10.18"))
        self.assertTrue(floors[0].specifier.contains("2026.10.19"))

    def test_certifi_fixed_in_every_distribution_profile(self):
        # GHSA-6q48-6c7w-9gw2 must not return through a bundled platform lock.
        fixed = Requirement("certifi>=2026.10.19")
        wheel_hashes = set()
        roots = [ROOT, *sorted((ROOT / "profiles").glob("*/requirements-agent.lock"))]
        self.assertEqual(len(roots), 4)
        for profile in roots:
            root = profile if profile.is_dir() else profile.parent
            with self.subTest(profile=str(root.relative_to(ROOT))):
                pins = [line.split() for line in (root / "requirements-agent.lock").read_text().splitlines()
                        if line.startswith("certifi==")]
                self.assertEqual(len(pins), 1)
                version = pins[0][0].split("==", 1)[1]
                self.assertTrue(fixed.specifier.contains(version))
                bom = json.loads((root / "sbom/python-agent.cdx.json").read_text())
                component = next(c for c in bom["components"] if c["name"] == "certifi")
                self.assertEqual(component["version"], version)
                digest = component["hashes"][0]["content"]
                self.assertEqual(pins[0][1:], ["--hash=sha256:" + digest])
                wheel_hashes.add(digest)
        self.assertEqual(len(wheel_hashes), 1, "All profiles use the same universal certifi wheel")

    def test_cryptography_floor_applies_where_fixed_wheels_exist(self):
        # cryptography 50 fixes CVE-2026-69247/69248/69249 but ships no Intel macOS wheel.
        project = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]
        floors = [Requirement(text) for text in project["optional-dependencies"]["agent"]
                  if Requirement(text).name == "cryptography"]
        self.assertEqual(len(floors), 1)
        floor = floors[0]
        self.assertTrue(floor.specifier.contains("50.0.2"))
        self.assertFalse(floor.specifier.contains("48.0.1"))
        for platform, machine, applies in (("win32", "AMD64", True), ("linux", "x86_64", True),
                                           ("darwin", "arm64", True), ("darwin", "x86_64", False)):
            with self.subTest(platform=platform, machine=machine):
                self.assertEqual(floor.marker.evaluate({"sys_platform": platform, "platform_machine": machine}),
                                 applies)


class OwnLicenseTests(unittest.TestCase):
    def test_project_code_is_mit_licensed(self):
        project = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]
        self.assertEqual(project.get("license"), "MIT")
        self.assertIn("LICENSE", project.get("license-files", []))
        text = (ROOT / "LICENSE").read_text()
        self.assertTrue(text.startswith("MIT License\n"))
        self.assertIn("Copyright (c) 2026 tedorigawa001\n", text)
        self.assertNotIn("<", text)  # no placeholder left


def write_files(root, relatives):
    for relative in relatives:
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("old")


class StaleEvidenceTests(unittest.TestCase):
    """Evidence of an older version must not survive regeneration (cryptography 48.0.1 once did)."""

    def generate(self, root, outputs, *options):
        with patch("scripts.generate_compliance.collect", return_value=(outputs, [])), \
                patch.object(sys, "argv", ["generate_compliance.py", "--output", str(root), *options]), \
                redirect_stdout(io.StringIO()) as printed:
            return main(), printed.getvalue()

    def test_regeneration_removes_evidence_of_older_versions(self):
        old_license = "third_party/licenses/pkg/1.0/pkg-1.0.dist-info/licenses/LICENSE"
        old_metadata = "third_party/metadata/pkg-1.0.METADATA"
        outputs = {"third_party/licenses/pkg/2.0/LICENSE": b"new", "third_party/metadata/pkg-2.0.METADATA": b"new"}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.assertEqual(self.generate(root, outputs)[0], 0)
            write_files(root, [old_license, old_metadata, "third_party/licenses/.DS_Store", "README.md"])

            code, printed = self.generate(root, outputs, "--check")
            self.assertEqual(code, 1)
            self.assertEqual(json.loads(printed), {"different_files": [], "stale_files": [old_license, old_metadata],
                                                   "unresolved": []})
            self.assertTrue((root / old_license).exists(), "--check must not remove anything")

            self.assertEqual(self.generate(root, outputs)[0], 0)
            self.assertFalse((root / "third_party/licenses/pkg/1.0").exists())
            self.assertFalse((root / old_metadata).exists())
            self.assertTrue((root / "third_party/licenses/.DS_Store").exists())  # the file manager's own
            self.assertTrue((root / "README.md").exists())  # outside the evidence folders
            self.assertEqual(self.generate(root, outputs, "--check")[0], 0)

    def test_notice_renamed_only_in_case_is_kept(self):
        # On macOS and Windows LICENSE and License are the same file.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_files(root, ["third_party/licenses/pkg/1.0/LICENSE"])
            self.assertEqual(self.generate(root, {"third_party/licenses/pkg/1.0/License": b"new"})[0], 0)
            folder = root / "third_party/licenses/pkg/1.0"
            self.assertEqual([path.name for path in folder.iterdir()], ["License"])
            self.assertEqual((folder / "License").read_bytes(), b"new")


@unittest.skipUnless(importlib.util.find_spec("jsonschema"), "jsonschema not installed")
class UnlistedEvidenceTests(unittest.TestCase):
    def test_evidence_the_manifest_does_not_list_is_reported(self):
        from scripts.validate_compliance import unlisted_evidence

        listed = ["third_party/licenses/pkg/2.0/LICENSE", "third_party/metadata/pkg-2.0.METADATA"]
        manifest = {"components": [{"metadata_path": listed[1], "notices": [{"path": listed[0]}]}]}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_files(root, [*listed, "third_party/licenses/pkg/1.0/LICENSE", "third_party/metadata/.DS_Store"])
            self.assertEqual(unlisted_evidence(root, manifest), ["third_party/licenses/pkg/1.0/LICENSE"])

    def test_committed_profiles_hold_only_listed_evidence(self):
        from scripts.validate_compliance import unlisted_evidence

        for root in [ROOT, *sorted(p for p in (ROOT / "profiles").iterdir() if p.is_dir())]:
            with self.subTest(profile=root.name):
                manifest = json.loads((root / "third_party/license-manifest.json").read_text())
                self.assertEqual(unlisted_evidence(root, manifest), [])


if __name__ == "__main__":
    unittest.main()
