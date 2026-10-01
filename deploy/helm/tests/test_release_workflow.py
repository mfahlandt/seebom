"""Release workflow contract tests.

The chart gained an mcp-server Deployment (#399) while the release workflow
kept publishing five images, so a chart released with `mcp.enabled=true` would
have pointed at an image that was never pushed. And a release candidate must
never move `:latest`. These tests pin both, without needing GitHub Actions:

- every first-party image the chart deploys is built by release.yml,
- `make images` builds the same set (it is how RCs get smoke-tested locally),
- the `:latest` tag is only emitted for final releases.

Run with python3 -m unittest discover -s deploy/helm/tests -v.
"""

from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[3]
TEMPLATES = ROOT / "deploy/helm/bomhort/templates"
WORKFLOW = ROOT / ".github/workflows/release.yml"
MAKEFILE = ROOT / "Makefile"


def chart_images():
    pattern = re.compile(r"\{\{ \.Values\.image\.repository \}\}/([a-z0-9-]+):")
    names = set()
    for template in TEMPLATES.glob("*.yaml"):
        names.update(pattern.findall(template.read_text()))
    return names


def workflow_images():
    text = WORKFLOW.read_text()
    matrix = re.search(r"^        component:\n(.*?)^    steps:", text, re.S | re.M)
    if matrix is None:
        raise AssertionError("component matrix not found in release.yml")
    return set(re.findall(r"^          - name: ([a-z0-9-]+)$", matrix.group(1), re.M))


def makefile_images():
    text = MAKEFILE.read_text()
    target = re.search(r"^images:.*?\n((?:\t.*\n)+)", text, re.M)
    if target is None:
        raise AssertionError("images target not found in Makefile")
    return set(re.findall(r"\$\(REPO\)/([a-z0-9-]+):\$\(TAG\)", target.group(1)))


class ReleaseWorkflowTest(unittest.TestCase):
    def test_chart_images_found(self):
        # Guard against the regex silently matching nothing.
        self.assertIn("api-gateway", chart_images())

    def test_release_publishes_every_chart_image(self):
        missing = chart_images() - workflow_images()
        self.assertFalse(
            missing,
            f"the chart deploys images release.yml never publishes: {sorted(missing)}",
        )

    def test_make_images_matches_release(self):
        self.assertEqual(makefile_images(), workflow_images())

    def test_latest_only_for_final_releases(self):
        lines = [line for line in WORKFLOW.read_text().splitlines() if ":latest" in line]
        self.assertTrue(lines, "release.yml no longer tags :latest at all")
        for line in lines:
            if line.strip().startswith("#"):
                continue
            self.assertIn(
                'PRERELEASE" != "true"',
                line,
                f"':latest' emitted without the pre-release guard: {line.strip()}",
            )

    def test_manual_runs_are_pre_releases_only(self):
        text = WORKFLOW.read_text()
        self.assertIn("workflow_dispatch:", text)
        self.assertIn("Manual runs publish pre-releases only", text)


if __name__ == "__main__":
    unittest.main()

