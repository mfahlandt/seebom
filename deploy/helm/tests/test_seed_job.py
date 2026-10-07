"""The seed job is opt-in, clones for real and cannot hang (#391).

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


def render(values=None, args=(), success=True):
    with tempfile.TemporaryDirectory() as directory:
        values_file = Path(directory) / "values.json"
        values_file.write_text(json.dumps(values or {}))
        result = subprocess.run(
            ["helm", "template", "test", str(CHART), "-f", str(values_file), *args],
            cwd=ROOT, text=True, capture_output=True, check=False,
        )
    if success:
        assert result.returncode == 0, result.stderr
        return result.stdout
    assert result.returncode != 0, result.stdout
    return result.stderr


def seed_job(rendered):
    match = re.search(
        r"# Source: bomhort/templates/job-seed-sboms\.yaml\n(.*?)(?=\n---|\Z)",
        rendered, re.DOTALL,
    )
    return match.group(1) if match else None


class SeedJobTest(unittest.TestCase):
    def test_not_rendered_unless_asked_for(self):
        for values in ({}, {"gitSync": {"enabled": False}},
                       {"gitSync": {"enabled": False}, "seedJob": {"sbomRepo": "https://example.org/x.git"}}):
            with self.subTest(values=values):
                self.assertIsNone(seed_job(render(values)))

    def test_deployment_examples_render_no_seed_job(self):
        for filename in ("examples/kind/values-kind.yaml",
                         "examples/kubernetes/values-production.yaml",
                         "examples/kubernetes/values-minimal.yaml",
                         "examples/kubernetes/values-cncf.yaml"):
            with self.subTest(filename=filename):
                self.assertIsNone(seed_job(render(args=("-f", str(ROOT / filename)))))

    def test_enabled_job_clones_and_has_a_deadline(self):
        job = seed_job(render({"gitSync": {"enabled": False},
                               "seedJob": {"enabled": True, "sbomRepo": "https://example.org/sboms.git",
                                           "sbomBranch": "release", "path": "sbom/"}}))
        self.assertIsNotNone(job)
        self.assertIn("activeDeadlineSeconds: 1800", job)
        self.assertRegex(job, r"image: docker\.io/alpine/git:v[\d.]+@sha256:[0-9a-f]{64}")
        self.assertIn('git clone --quiet --depth 1 --single-branch --branch "$SBOM_BRANCH" "$SBOM_REPO"', job)
        self.assertIn('value: "https://example.org/sboms.git"', job)
        self.assertIn('value: "release"', job)
        self.assertIn('value: "sbom/"', job)
        self.assertNotIn("until [ -f", job, "the old wait-for-nothing loop is back")
        self.assertNotIn("\n              #", job, "commented-out script lines")
        self.assertIn("claimName: bomhort-sbom-data", job)

    def test_private_repo_secret_is_wired(self):
        job = seed_job(render({"gitSync": {"enabled": False},
                               "seedJob": {"enabled": True, "secretName": "git-creds"}}))
        self.assertIn("name: git-creds", job)
        self.assertIn("credential.helper", job)

    def test_refuses_to_run_next_to_git_sync(self):
        err = render({"seedJob": {"enabled": True}}, success=False)
        self.assertIn("seedJob.enabled and gitSync.enabled are mutually exclusive", err)


if __name__ == "__main__":
    unittest.main()
