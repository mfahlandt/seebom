"""licenseExceptions/licensePolicy.existingConfigMap (#397).

GitOps tools render the chart themselves and cannot pass --set-file, so a large
reviewed exceptions file had to be inlined into the Argo CD Application. With
existingConfigMap the chart mounts a ConfigMap the operator manages instead.

Run with python3 -m unittest discover -s deploy/helm/tests -v (requires helm).
"""

import json
from pathlib import Path
import re
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[3]
CHART = ROOT / "deploy/helm/bomhort"
DEPLOYMENTS = ("api-gateway", "parsing-worker")

CASES = {
    "licenseExceptions": ("license-exceptions", "license-exceptions.json"),
    "licensePolicy": ("license-policy", "license-policy.json"),
}


def documents(rendered):
    """Map 'templates/<file>' -> rendered document text."""
    docs = {}
    for doc in rendered.split("\n---\n"):
        match = re.search(r"# Source: bomhort/(templates/\S+)", doc)
        if match:
            docs[match.group(1)] = doc
    return docs


def volume(deployment, name):
    """The volumes: entry for name, up to the next volume."""
    volumes = deployment.split("\n      volumes:\n", 1)[1]
    match = re.search(r"        - name: %s\n(.*?)(?=\n        - name: |\Z)" % re.escape(name),
                      volumes, re.DOTALL)
    assert match, "volume %s not found" % name
    return match.group(1)


class ExistingConfigMapTest(unittest.TestCase):
    def render(self, values=None, success=True):
        with tempfile.TemporaryDirectory() as directory:
            values_file = Path(directory) / "values.json"
            values_file.write_text(json.dumps(values or {}))
            result = subprocess.run(
                ["helm", "template", "rel", str(CHART), "-f", str(values_file)],
                cwd=ROOT, text=True, capture_output=True, check=False,
            )
        if success:
            self.assertEqual(result.returncode, 0, result.stderr)
            return documents(result.stdout)
        self.assertNotEqual(result.returncode, 0, "render should have failed")
        return result.stderr

    def deployments(self, docs):
        return {d: docs["templates/deployment-%s.yaml" % d] for d in DEPLOYMENTS}

    def test_default_renders_and_mounts_the_chart_configmap(self):
        docs = self.render()
        for key, (name, _) in CASES.items():
            with self.subTest(key=key):
                self.assertIn("templates/configmap-%s.yaml" % name, docs)
                for deployment in self.deployments(docs).values():
                    entry = volume(deployment, name)
                    self.assertIn("name: rel-%s" % name, entry)
                    self.assertNotIn("items:", entry)

    def test_existing_configmap_is_mounted_and_none_rendered(self):
        for key, (name, file) in CASES.items():
            with self.subTest(key=key):
                docs = self.render({key: {"existingConfigMap": "reviewed-rules"}})
                self.assertNotIn("templates/configmap-%s.yaml" % name, docs)
                for deployment in self.deployments(docs).values():
                    entry = volume(deployment, name)
                    self.assertIn("name: reviewed-rules", entry)
                    self.assertIn("- key: %s\n" % file, entry)
                    # The path inside the volume must stay the file name the
                    # binaries expect.
                    self.assertIn("path: %s" % file, entry)
                    if key == "licenseExceptions":
                        # A directory mount, so edits reach the running pods.
                        self.assertNotIn("subPath: %s" % file, deployment)
                    else:
                        self.assertIn("subPath: %s" % file, deployment)

    def test_existing_configmap_key_is_mapped_to_the_expected_file(self):
        for key, (name, file) in CASES.items():
            with self.subTest(key=key):
                docs = self.render({key: {"existingConfigMap": "upstream",
                                          "existingConfigMapKey": "exceptions.json"}})
                for deployment in self.deployments(docs).values():
                    entry = volume(deployment, name)
                    self.assertIn("- key: exceptions.json\n", entry)
                    self.assertIn("path: %s" % file, entry)

    def test_custom_and_existing_configmap_together_fail(self):
        for key, custom in (
            ("licenseExceptions", {"blanketExceptions": [], "exceptions": []}),
            ("licenseExceptions", '{"blanketExceptions": [], "exceptions": []}'),
            ("licensePolicy", '{"permissive": ["MIT"], "copyleft": []}'),
        ):
            with self.subTest(key=key, custom=type(custom).__name__):
                error = self.render({key: {"existingConfigMap": "x", "custom": custom}},
                                    success=False)
                self.assertIn("%s.existingConfigMap" % key, error)
                self.assertIn("%s.custom" % key, error)

    def test_exceptions_never_roll_the_pods(self):
        # Edits to either ConfigMap reach the pods through the directory
        # mount; the binaries reload and re-check stored results themselves.
        for values in ({}, {"licenseExceptions": {"existingConfigMap": "reviewed-rules"}}):
            docs = self.render(values)
            for deployment in self.deployments(docs).values():
                self.assertNotIn("checksum/license-exceptions", deployment)
                self.assertNotIn("bomhort.io/license-exceptions-configmap", deployment)

    def test_disabled_ignores_existing_configmap(self):
        for key, (name, _) in CASES.items():
            with self.subTest(key=key):
                docs = self.render({key: {"enabled": False, "existingConfigMap": "x"}})
                self.assertNotIn("templates/configmap-%s.yaml" % name, docs)
                for deployment in self.deployments(docs).values():
                    self.assertNotIn("name: %s\n" % name, deployment)


if __name__ == "__main__":
    unittest.main()
