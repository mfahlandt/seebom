"""The seed job is gone, and values that still configure it are refused (#391).

The job's git clone had been commented out since March 2026; what shipped was a
Job that waited forever for a file nothing created, rendered for everyone with
gitSync disabled — S3 users included. These tests pin the removal: no Job is
rendered in any source mode, and a `seedJob` block fails the render with a
message that says what to use instead.

Run with python3 -m unittest discover -s deploy/helm/tests -v (requires helm).
"""

import json
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[3]
CHART = ROOT / "deploy/helm/bomhort"


class SeedJobRemovedTest(unittest.TestCase):
    def render(self, values=None, success=True):
        with tempfile.TemporaryDirectory() as directory:
            values_file = Path(directory) / "values.json"
            values_file.write_text(json.dumps(values or {}))
            result = subprocess.run(
                ["helm", "template", "test", str(CHART), "-f", str(values_file)],
                cwd=ROOT, text=True, capture_output=True, check=False,
            )
        if success:
            self.assertEqual(result.returncode, 0, result.stderr)
            return result.stdout
        self.assertNotEqual(result.returncode, 0, "render should have failed")
        return result.stderr

    def test_no_seed_job_in_any_source_mode(self):
        for name, values in {
            "git-sync": {},
            "pvc": {"gitSync": {"enabled": False}},
            "s3": {"gitSync": {"enabled": False},
                   "s3": {"buckets": '[{"name":"sboms","region":"us-east-1"}]'}},
        }.items():
            with self.subTest(mode=name):
                output = self.render(values)
                self.assertNotIn("seed-sboms", output)
                self.assertNotIn("/data/sboms/ready", output)

    def test_pvc_mode_still_creates_the_volume(self):
        output = self.render({"gitSync": {"enabled": False}})
        self.assertIn("kind: PersistentVolumeClaim", output)
        self.assertIn("name: bomhort-sbom-data", output)

    def test_seed_job_values_are_refused(self):
        for seed in ({"sbomRepo": "https://github.com/my-org/sboms.git"},
                     {"sbomBranch": "main"}):
            with self.subTest(seedJob=seed):
                error = self.render({"seedJob": seed}, success=False)
                self.assertIn("seedJob was removed", error)
                self.assertIn("s3.buckets", error)
                self.assertIn("#391", error)

    def test_empty_seed_job_block_is_harmless(self):
        self.render({"seedJob": {}})
        self.render({"seedJob": None})

    def test_legacy_exceptions_url_keeps_its_specific_message(self):
        error = self.render({"seedJob": {"cncfExceptionsURL": "https://example.org/x.json"}},
                            success=False)
        self.assertIn("seedJob.cncfExceptionsURL is no longer supported", error)


if __name__ == "__main__":
    unittest.main()
