"""Run with python3 -m unittest discover -s deploy/helm/tests -v (requires helm)."""

import json
from pathlib import Path
import re
import subprocess
import tempfile
import textwrap
import unittest


ROOT = Path(__file__).resolve().parents[3]
CHART = ROOT / "deploy/helm/bomhort"


class LicenseExceptionsTemplatesTest(unittest.TestCase):
    def render(self, values=None, args=(), success=True):
        with tempfile.TemporaryDirectory() as directory:
            values_file = Path(directory) / "values.json"
            values_file.write_text(json.dumps(values or {}))
            result = subprocess.run(
                ["helm", "template", "test", str(CHART), "-f", str(values_file), *args],
                cwd=ROOT, text=True, capture_output=True, check=False,
            )
        if success:
            self.assertEqual(result.returncode, 0, result.stderr)
        else:
            self.assertNotEqual(result.returncode, 0, result.stdout)
        return result.stdout if success else result.stderr

    def exceptions(self, rendered):
        match = re.search(r"^  license-exceptions\.json: \|-\n((?:    .*\n|\n)+)", rendered, re.MULTILINE)
        self.assertIsNotNone(match, rendered)
        return json.loads(textwrap.dedent(match.group(1)))

    def checksums(self, rendered):
        result = {}
        for component in ("api-gateway", "parsing-worker"):
            match = re.search(
                rf"# Source: bomhort/templates/deployment-{component}\.yaml\n(.*?)(?=\n---|\Z)",
                rendered, re.DOTALL,
            )
            self.assertIsNotNone(match)
            checksum = re.search(r"checksum/license-exceptions: ([0-9a-f]{64})", match.group(1))
            self.assertIsNotNone(checksum)
            result[component] = checksum.group(1)
        self.assertEqual(result["api-gateway"], result["parsing-worker"])
        return result

    def test_defaults_and_deployment_examples_are_empty(self):
        for filename in (None, "examples/kind/values-kind.yaml",
                         "examples/kubernetes/values-production.yaml",
                         "examples/kubernetes/values-minimal.yaml"):
            with self.subTest(filename=filename):
                output = self.render(args=("-f", str(ROOT / filename)) if filename else ())
                config = self.exceptions(output)
                self.assertEqual(config["blanketExceptions"], [])
                self.assertEqual(config["exceptions"], [])
                self.assertNotIn("Downloading CNCF license exceptions", output)
                self.checksums(output)

    def test_mapping_json_string_and_set_file(self):
        config = {
            "version": "1.0.0", "blanketExceptions": [], "exceptions": [
                {"id": "own-rule", "package": "example.org/team/lib", "license": "MPL-2.0",
                 "project": "my-sbom", "status": "approved", "comment": 'Quotes " and {{ literal }}'}
            ],
        }
        outputs = []
        for custom in (config, json.dumps(config)):
            output = self.render({"licenseExceptions": {"custom": custom}})
            self.assertEqual(self.exceptions(output), config)
            outputs.append(self.checksums(output))
        with tempfile.TemporaryDirectory() as directory:
            filename = Path(directory) / "exceptions.json"
            filename.write_text(json.dumps(config))
            output = self.render(args=("--set-file", f"licenseExceptions.custom={filename}"))
            self.assertEqual(self.exceptions(output), config)
            outputs.append(self.checksums(output))
        self.assertEqual(outputs[0], outputs[1])
        self.assertEqual(outputs[0], outputs[2])
        self.assertNotEqual(outputs[0], self.checksums(self.render()))

    def test_explicit_empty_and_revocation_change_both_rollouts(self):
        config = {"blanketExceptions": [], "exceptions": [
            {"id": "own-rule", "package": "lib", "license": "MPL-2.0", "status": "approved"}
        ]}
        approved = self.checksums(self.render({"licenseExceptions": {"custom": config}}))
        config["exceptions"][0]["status"] = "revoked"
        revoked = self.checksums(self.render({"licenseExceptions": {"custom": config}}))
        config["exceptions"] = []
        empty_output = self.render({"licenseExceptions": {"custom": config}})
        self.assertEqual(self.exceptions(empty_output), config)
        empty = self.checksums(empty_output)
        for component in approved:
            self.assertNotEqual(approved[component], revoked[component])
            self.assertNotEqual(revoked[component], empty[component])

    def test_disabled_removes_configmap_checksum_and_mounts(self):
        output = self.render({"licenseExceptions": {"enabled": False}})
        self.assertNotIn("configmap-license-exceptions.yaml", output)
        self.assertNotIn("checksum/license-exceptions", output)
        self.assertNotIn("name: license-exceptions", output)

    def test_custom_mount_path_matches_environment(self):
        output = self.render({"licenseExceptions": {"mountPath": "/custom/exceptions.json"}})
        self.assertIn('EXCEPTIONS_FILE: "/custom/exceptions.json"', output)
        self.assertEqual(output.count("mountPath: /custom/exceptions.json"), 2)
        self.assertEqual(output.count("subPath: license-exceptions.json"), 2)

    def test_invalid_custom_config_is_rejected(self):
        for custom in ("{", "null", "[]", "{}", "42", {}, [], 0, False, {"exceptions": []},
                       {"exceptions": [], "blanketExceptions": None},
                       {"exceptions": "wrong", "blanketExceptions": []}):
            with self.subTest(custom=custom):
                error = self.render({"licenseExceptions": {"custom": custom}}, success=False)
                self.assertRegex(error, r"licenseExceptions\.custom|mustFromJson")

    def test_legacy_download_setting_requires_explicit_migration(self):
        error = self.render({"seedJob": {"cncfExceptionsURL": "https://example.org/exceptions.json"}}, success=False)
        self.assertIn("licenseExceptions.custom", error)


if __name__ == "__main__":
    unittest.main()
