"""Helm template tests for the ownership dimensions (#131, #138, #57).

Run with python3 -m unittest discover -s deploy/helm/tests -v (requires helm).
"""

import json
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[3]
CHART = ROOT / "deploy/helm/bomhort"


class OwnershipTemplatesTest(unittest.TestCase):
    def render(self, values=None):
        with tempfile.TemporaryDirectory() as directory:
            values_file = Path(directory) / "values.json"
            values_file.write_text(json.dumps(values or {}))
            result = subprocess.run(
                ["helm", "template", "test", str(CHART), "-f", str(values_file)],
                cwd=ROOT, text=True, capture_output=True, check=False,
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout

    def test_defaults_are_empty_and_derivation_is_off(self):
        out = self.render()
        self.assertIn('CLUSTER_NAME: ""', out)
        self.assertIn('NAMESPACE: ""', out)
        self.assertIn('PROJECT: ""', out)
        # Derivation must be opt-in: an empty layout changes nothing about how
        # existing deployments label their data.
        self.assertIn('INGEST_PATH_LAYOUT: ""', out)

    def test_values_are_forwarded(self):
        out = self.render({"ownership": {
            "cluster": "prod-eu",
            "namespace": "payments",
            "project": "payment-service",
            "pathLayout": "cluster/namespace/project",
        }})
        self.assertIn('CLUSTER_NAME: "prod-eu"', out)
        self.assertIn('NAMESPACE: "payments"', out)
        self.assertIn('PROJECT: "payment-service"', out)
        self.assertIn('INGEST_PATH_LAYOUT: "cluster/namespace/project"', out)

    def test_partial_values_leave_the_rest_empty(self):
        out = self.render({"ownership": {"namespace": "team-a"}})
        self.assertIn('NAMESPACE: "team-a"', out)
        self.assertIn('CLUSTER_NAME: ""', out)
        self.assertIn('PROJECT: ""', out)

    def test_every_workload_sees_the_config(self):
        """All three binaries read these vars, so all must consume the ConfigMap.

        The watcher stamps the dimensions onto queue rows, the worker copies
        them onto every data row, and the gateway uses them as the upload
        defaults — a workload missing the envFrom would silently write
        unlabelled data.
        """
        out = self.render({"ownership": {"cluster": "prod-eu"}})
        for name in ("test-ingestion-watcher",
                     "test-parsing-worker",
                     "test-api-gateway"):
            docs = [d for d in out.split("---")
                    if ("name: %s\n" % name) in d and "kind: Service" not in d]
            self.assertTrue(docs, "no workload manifest rendered for %s" % name)
            self.assertTrue(
                any("test-config" in d for d in docs),
                "%s does not consume the config ConfigMap" % name,
            )


class MigrationConfigMapTest(unittest.TestCase):
    """The chart ships its own copy of db/migrations; drift means a
    Kubernetes deployment silently never applies a migration.

    013 and 014 were missing from the chart before #138/#57 landed, so this
    guards the whole directory rather than just the new file.
    """

    def test_every_db_migration_is_shipped_in_the_chart(self):
        db = sorted(p.name for p in (ROOT / "db/migrations").glob("*.sql"))
        chart = sorted(p.name for p in (CHART / "migrations").glob("*.sql"))
        missing = [m for m in db if m not in chart]
        self.assertEqual(missing, [], "missing from the Helm chart: %s" % missing)

    def test_shipped_migrations_are_byte_identical(self):
        for path in (ROOT / "db/migrations").glob("*.sql"):
            shipped = CHART / "migrations" / path.name
            self.assertTrue(shipped.exists(), "%s not shipped" % path.name)
            self.assertEqual(
                path.read_bytes(), shipped.read_bytes(),
                "%s differs between db/migrations and the Helm chart" % path.name,
            )


if __name__ == "__main__":
    unittest.main()


