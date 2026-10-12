import ast
import importlib.metadata as metadata
import sys
import tomllib
import unittest
from itertools import chain
from types import SimpleNamespace

from scripts.generate_compliance import ROOT, Requirement, active_requirement, canonicalize_name, resolve_graph


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
            for node in ast.walk(ast.parse(source.read_text())):
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


if __name__ == "__main__":
    unittest.main()
