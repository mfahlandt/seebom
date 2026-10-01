"""Helm template tests for the project groups mapping file (parent grouping).

Run with python3 -m unittest discover -s deploy/helm/tests -v (requires helm).
Standard library only, like the other chart tests.
"""

import json
from pathlib import Path
import subprocess
import tempfile
import textwrap
import unittest


ROOT = Path(__file__).resolve().parents[3]
CHART = ROOT / "deploy/helm/bomhort"


class ProjectGroupsTemplatesTest(unittest.TestCase):
    def render(self, values=None, show_only=None, expect_ok=True):
        with tempfile.TemporaryDirectory() as directory:
            values_file = Path(directory) / "values.json"
            values_file.write_text(json.dumps(values or {}))
            cmd = ["helm", "template", "test", str(CHART), "-f", str(values_file)]
            if show_only:
                cmd += ["--show-only", show_only]
            result = subprocess.run(cmd, cwd=ROOT, text=True, capture_output=True, check=False)
        if expect_ok:
            self.assertEqual(result.returncode, 0, result.stderr)
        return result

    def rules(self, values=None):
        """The rendered project-groups.json, parsed."""
        out = self.render(values, "templates/configmap-project-groups.yaml").stdout
        block = out.split("project-groups.json: |-\n", 1)[1]
        return json.loads(textwrap.dedent(block))

    def gateway(self, values=None):
        return self.render(values, "templates/deployment-api-gateway.yaml").stdout

    def config(self, values=None):
        return self.render(values, "templates/configmap.yaml").stdout

    def test_default_renders_an_empty_rule_file_and_mounts_it_as_a_directory(self):
        self.assertEqual(self.rules(), {"version": "1.0.0", "groups": []})
        self.assertIn('PROJECT_GROUPS_FILE: "/data/config/project-groups/project-groups.json"', self.config())
        self.assertIn('PARENT: ""', self.config())

        gw = self.gateway()
        # A directory mount without subPath: subPath mounts never see
        # ConfigMap updates, and the gateway re-reads the file when it changes.
        mount = gw.split("- name: project-groups\n", 1)[1].split("- name:", 1)[0]
        self.assertIn("mountPath: /data/config/project-groups", mount)
        self.assertNotIn("subPath", mount)
        volume = gw.rsplit("- name: project-groups\n", 1)[1]
        self.assertIn("name: test-project-groups", volume)
        self.assertIn("optional: true", volume)

    def test_groups_are_rendered_in_order(self):
        rules = self.rules({"projectGroups": {"groups": [
            {"parent": "argo", "match": {"projects": ["argo-cd/*"]}},
            {"standalone": True, "match": {"owners": ["kubernetes-sigs"]}, "reason": "shared org"},
        ]}})
        self.assertEqual(rules["groups"][0]["parent"], "argo")
        self.assertEqual(rules["groups"][0]["match"]["projects"], ["argo-cd/*"])
        self.assertTrue(rules["groups"][1]["standalone"])

    def test_existing_configmap_replaces_the_rendered_one(self):
        values = {"projectGroups": {"existingConfigMap": "my-groups"}}
        self.assertNotIn("test-project-groups", self.render(values).stdout)
        self.assertIn("name: my-groups", self.gateway(values).rsplit("- name: project-groups\n", 1)[1])

    def test_disabled_mounts_nothing(self):
        values = {"projectGroups": {"enabled": False}}
        out = self.render(values).stdout
        self.assertNotIn("project-groups", out.replace("PROJECT_GROUPS_FILE", ""))
        self.assertIn('PROJECT_GROUPS_FILE: ""', self.config(values))

    def test_parent_default_is_forwarded(self):
        self.assertIn('PARENT: "Payments Platform"', self.config({"ownership": {"parent": "Payments Platform"}}))

    def test_values_from_an_older_chart_still_render(self):
        # `helm upgrade --reuse-values` from a chart that predates
        # projectGroups carries no such key. That must not break the
        # upgrade; it means "no mapping file", automatic grouping still works.
        values = {"projectGroups": None}
        out = self.render(values).stdout
        self.assertNotIn("test-project-groups", out)
        self.assertIn('PROJECT_GROUPS_FILE: ""', self.config(values))

    def test_invalid_groups_fail_the_render(self):
        cases = {
            "needs a parent or standalone": [{"match": {"projects": ["x"]}}],
            "sets both parent and standalone": [{"parent": "p", "standalone": True, "match": {"projects": ["x"]}}],
            "needs a match": [{"parent": "p"}],
        }
        for message, groups in cases.items():
            with self.subTest(message):
                result = self.render({"projectGroups": {"groups": groups}}, expect_ok=False)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(message, result.stderr)


if __name__ == "__main__":
    unittest.main()
