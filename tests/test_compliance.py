import unittest
from types import SimpleNamespace

from scripts.generate_compliance import active_requirement, resolve_graph


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


if __name__ == "__main__":
    unittest.main()
