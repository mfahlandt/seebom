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

    def deployments(self, rendered):
        result = {}
        for component in ("api-gateway", "parsing-worker"):
            match = re.search(
                rf"# Source: bomhort/templates/deployment-{component}\.yaml\n(.*?)(?=\n---|\Z)",
                rendered, re.DOTALL,
            )
            self.assertIsNotNone(match)
            result[component] = match.group(1)
        return result

    def assert_live_reload(self, rendered):
        """The rules reach running pods by themselves: no rollout checksum,
        and a directory mount, never a subPath (which never sees updates)."""
        self.assertNotIn("checksum/license-exceptions", rendered)
        for deployment in self.deployments(rendered).values():
            mount = deployment.split("- name: license-exceptions\n", 1)[1].split("- name:", 1)[0]
            self.assertIn("mountPath: /data/config/license-exceptions\n", mount)
            self.assertNotIn("subPath", mount)

    def config(self, rendered):
        return dict(re.findall(r'^  (EXCEPTIONS_[A-Z_]+): "(.*)"$', rendered, re.MULTILINE))

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
                self.assert_live_reload(output)
                self.assertEqual(self.config(output), {
                    "EXCEPTIONS_FILE": "/data/config/license-exceptions/license-exceptions.json",
                    "EXCEPTIONS_SOURCE": "",
                    "EXCEPTIONS_REFRESH_INTERVAL": "60s",
                })

    def test_mapping_json_string_and_set_file(self):
        config = {
            "version": "1.0.0", "blanketExceptions": [], "exceptions": [
                {"id": "own-rule", "package": "example.org/team/lib", "license": "MPL-2.0",
                 "project": "my-sbom", "status": "approved", "comment": 'Quotes " and {{ literal }}'}
            ],
        }
        for custom in (config, json.dumps(config)):
            output = self.render({"licenseExceptions": {"custom": custom}})
            self.assertEqual(self.exceptions(output), config)
        with tempfile.TemporaryDirectory() as directory:
            filename = Path(directory) / "exceptions.json"
            filename.write_text(json.dumps(config))
            output = self.render(args=("--set-file", f"licenseExceptions.custom={filename}"))
            self.assertEqual(self.exceptions(output), config)

    def test_granting_and_revoking_change_only_the_configmap(self):
        # The pods pick the change up and re-check stored results; rolling
        # them would only add churn.
        config = {"blanketExceptions": [], "exceptions": [
            {"id": "own-rule", "package": "lib", "license": "MPL-2.0", "status": "approved"}
        ]}
        approved = self.render({"licenseExceptions": {"custom": config}})
        config["exceptions"][0]["status"] = "revoked"
        revoked = self.render({"licenseExceptions": {"custom": config}})
        config["exceptions"] = []
        empty = self.render({"licenseExceptions": {"custom": config}})
        self.assertEqual(self.exceptions(empty), config)
        self.assertNotEqual(self.exceptions(approved), self.exceptions(revoked))
        self.assertEqual(self.deployments(approved), self.deployments(revoked))
        self.assertEqual(self.deployments(revoked), self.deployments(empty))

    def test_disabled_removes_configmap_checksum_and_mounts(self):
        output = self.render({"licenseExceptions": {"enabled": False}})
        self.assertNotIn("configmap-license-exceptions.yaml", output)
        self.assertNotIn("checksum/license-exceptions", output)
        self.assertNotIn("name: license-exceptions", output)

    def test_custom_mount_path_matches_environment(self):
        output = self.render({"licenseExceptions": {"mountPath": "/custom/exceptions.json"}})
        self.assertEqual(self.config(output)["EXCEPTIONS_FILE"], "/custom/exceptions.json")
        self.assertEqual(output.count("mountPath: /custom\n"), 2)
        self.assertNotIn("subPath: license-exceptions.json", output)
        # The chart's ConfigMap key is mapped to the file name the pods read.
        self.assertEqual(output.count("- key: license-exceptions.json\n                path: exceptions.json"), 2)

    def test_legacy_default_mount_path_moves_to_its_own_directory(self):
        # Still in the values after `helm upgrade --reuse-values` from 0.7; a
        # directory mount of /data/config would collide with the policy.
        output = self.render({"licenseExceptions": {"mountPath": "/data/config/license-exceptions.json"}})
        self.assertEqual(self.config(output)["EXCEPTIONS_FILE"],
                         "/data/config/license-exceptions/license-exceptions.json")
        self.assert_live_reload(output)

    def test_mount_path_sharing_a_directory_is_rejected(self):
        for path in ("/data/config/exceptions.json", "/data/sboms/exceptions.json", "/data/exceptions.json", "/exceptions.json"):
            with self.subTest(path=path):
                error = self.render({"licenseExceptions": {"mountPath": path}}, success=False)
                self.assertIn("licenseExceptions.mountPath", error)

    def test_remote_source_mounts_nothing(self):
        for source in ("https://example.org/governance/license-exceptions.json",
                       "s3://governance/bomhort/license-exceptions.json"):
            with self.subTest(source=source):
                output = self.render({"licenseExceptions": {"source": source, "refreshInterval": "5m"}})
                self.assertNotIn("configmap-license-exceptions.yaml", output)
                self.assertNotIn("name: license-exceptions", output)
                self.assertNotIn("EXCEPTIONS_SOURCE_TOKEN", output)
                self.assertEqual(self.config(output)["EXCEPTIONS_SOURCE"], source)
                self.assertEqual(self.config(output)["EXCEPTIONS_REFRESH_INTERVAL"], "5m")

    def test_source_token_comes_from_a_secret_in_both_deployments(self):
        output = self.render({"licenseExceptions": {
            "source": "https://example.org/x.json",
            "sourceTokenSecret": {"name": "governance-token", "key": "pat"},
        }})
        for deployment in self.deployments(output).values():
            env = deployment.split("- name: EXCEPTIONS_SOURCE_TOKEN\n", 1)[1].split("- name:", 1)[0]
            self.assertIn("name: governance-token", env)
            self.assertIn("key: pat", env)
            self.assertIn("env:", deployment)
        self.assertNotIn("governance-token", self.render({"licenseExceptions": {
            "enabled": False, "source": "https://example.org/x.json",
            "sourceTokenSecret": {"name": "governance-token"},
        }}))

    def test_refresh_interval(self):
        for value, expected in ((0, "0"), ("0", "0"), ("90s", "90s"), ("1h30m", "1h30m")):
            with self.subTest(value=value):
                output = self.render({"licenseExceptions": {"refreshInterval": value}})
                self.assertEqual(self.config(output)["EXCEPTIONS_REFRESH_INTERVAL"], expected)
        for value in ("soon", "60", "-1s", "1d"):
            with self.subTest(value=value):
                error = self.render({"licenseExceptions": {"refreshInterval": value}}, success=False)
                self.assertIn("licenseExceptions.refreshInterval", error)

    def test_invalid_source_settings_are_rejected(self):
        for values in (
            {"source": "http://example.org/x.json"},
            {"source": "file:///etc/passwd"},
            {"source": "https://example.org/x.json", "existingConfigMap": "x"},
            {"source": "https://example.org/x.json", "custom": {"blanketExceptions": [], "exceptions": []}},
            {"sourceTokenSecret": {"name": "token-without-source"}},
        ):
            with self.subTest(values=values):
                error = self.render({"licenseExceptions": values}, success=False)
                self.assertIn("licenseExceptions.", error)

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
        self.assertIn("licenseExceptions.source", error)


if __name__ == "__main__":
    unittest.main()
