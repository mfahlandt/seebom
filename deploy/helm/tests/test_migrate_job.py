"""The schema-migration Job is named after what it runs, not the Helm revision.

Argo CD renders the chart with `helm template`, where .Release.Revision is
always 1. The Job was therefore always `<release>-migrate-1`: created once,
never re-run when a release added migrations (production ran 0.8.0 code
against a 0.7 schema), and every later change to its immutable pod template
failed the Argo sync. These tests pin the replacement:

- the name is stable for identical input,
- it changes when a migration file or the Job spec changes (new Job runs),
- the password comes from userPasswordSecret when that is enabled,
- the Job fails instead of hanging,
- it is an ordinary resource, not a Helm hook: a pre-install hook runs before
  its ConfigMap, Secret and ClickHouse exist.

Run with python3 -m unittest discover -s deploy/helm/tests -v (requires helm).
"""

import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[3]
CHART = ROOT / "deploy/helm/bomhort"


def render(chart=CHART, values=None, release="test"):
    with tempfile.TemporaryDirectory() as directory:
        values_file = Path(directory) / "values.json"
        values_file.write_text(json.dumps(values or {}))
        result = subprocess.run(
            ["helm", "template", release, str(chart), "-f", str(values_file),
             "--show-only", "templates/job-migrate.yaml"],
            cwd=ROOT, text=True, capture_output=True, check=False,
        )
    if result.returncode != 0:
        raise AssertionError(result.stderr)
    return result.stdout


def job_name(output):
    match = re.search(r"^  name: (\S+)$", output, re.MULTILINE)
    assert match, output
    return match.group(1)


class MigrateJobNameTest(unittest.TestCase):
    def test_name_does_not_use_the_release_revision(self):
        self.assertRegex(job_name(render()), r"^test-migrate-[0-9a-f]{10}$")

    def test_name_is_stable_for_identical_input(self):
        self.assertEqual(job_name(render()), job_name(render()))

    def test_name_changes_with_the_job_spec(self):
        image = "docker.io/clickhouse/clickhouse-server:25.3"
        changed = render(values={"clickhouse": {"installation": {"podTemplate": {"containerImage": image}}}})
        self.assertIn(image, changed)
        self.assertNotEqual(job_name(render()), job_name(changed))

    def test_name_changes_when_a_migration_is_added(self):
        with tempfile.TemporaryDirectory() as directory:
            chart = Path(directory) / "bomhort"
            shutil.copytree(CHART, chart)
            before = job_name(render(chart))
            (chart / "migrations/999_test.up.sql").write_text(
                "ALTER TABLE sboms ADD COLUMN IF NOT EXISTS test String DEFAULT '';\n")
            after = render(chart)
        self.assertIn("999_test.up.sql", after)
        self.assertNotEqual(before, job_name(after))

    def test_name_changes_when_a_migration_is_edited(self):
        with tempfile.TemporaryDirectory() as directory:
            chart = Path(directory) / "bomhort"
            shutil.copytree(CHART, chart)
            before = job_name(render(chart))
            first = sorted((chart / "migrations").glob("*.sql"))[0]
            first.write_text(first.read_text() + "\n-- edited\n")
            self.assertNotEqual(before, job_name(render(chart)))

    def test_name_fits_a_kubernetes_name(self):
        self.assertLessEqual(len(job_name(render(release="bomhort"))), 63)

    def test_job_is_not_a_hook(self):
        self.assertNotIn("helm.sh/hook", render())


class MigrateJobPasswordTest(unittest.TestCase):
    def test_chart_secret_by_default(self):
        output = render()
        self.assertIn("name: test-secret", output)
        self.assertIn("key: CLICKHOUSE_PASSWORD", output)

    def test_user_password_secret_when_enabled(self):
        # The chart renders no <release>-secret in this mode, so the Job must
        # not reference it.
        output = render(values={"clickhouse": {"userPasswordSecret": {
            "enabled": True, "secretName": "clickhouse-password", "key": "password"}}})
        self.assertIn("name: clickhouse-password", output)
        self.assertIn("key: password", output)
        self.assertNotIn("test-secret", output)


class MigrateJobFailsVisiblyTest(unittest.TestCase):
    def script(self):
        result = subprocess.run(
            ["helm", "template", "test", str(CHART),
             "--show-only", "templates/configmap-migrations.yaml"],
            cwd=ROOT, text=True, capture_output=True, check=True,
        )
        return result.stdout

    def test_active_deadline_default_and_override(self):
        self.assertIn("activeDeadlineSeconds: 3600", render())
        self.assertIn("activeDeadlineSeconds: 600",
                      render(values={"migrations": {"activeDeadlineSeconds": 600}}))

    def test_wait_loop_is_bounded(self):
        script = self.script()
        self.assertIn('if [ "$tries" -ge 100 ]; then', script)
        # The client's error is kept, not discarded, so the log says why.
        self.assertNotIn('--query="SELECT 1" >/dev/null', script)
        self.assertIn("ingestion_queue_created_at_datetime64", script)

    def test_rejected_credentials_fail_at_once(self):
        script = self.script()
        self.assertIn("*AUTHENTICATION_FAILED*|*UNKNOWN_USER*|*REQUIRED_PASSWORD*)", script)


if __name__ == "__main__":
    unittest.main()
