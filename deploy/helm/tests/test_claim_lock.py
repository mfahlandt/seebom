"""The parsing worker refuses to start in-cluster without POD_NAMESPACE, and
its Lease lock needs get/create/update on coordination.k8s.io leases. These
tests pin what the worker's claimlock.New requires of the chart.

Run with python3 -m unittest discover -s deploy/helm/tests -v (requires helm).
"""

import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
CHART = ROOT / "deploy/helm/bomhort"


def render(show):
    result = subprocess.run(
        ["helm", "template", "test", str(CHART), "--show-only", show],
        cwd=ROOT, text=True, capture_output=True, check=False,
    )
    if result.returncode != 0:
        raise AssertionError(result.stderr)
    return result.stdout


class ClaimLockTest(unittest.TestCase):
    def test_worker_gets_namespace_and_service_account(self):
        output = render("templates/deployment-parsing-worker.yaml")
        self.assertIn("serviceAccountName: test-parsing-worker", output)
        self.assertIn("- name: POD_NAMESPACE", output)
        self.assertIn("fieldPath: metadata.namespace", output)
        # Old and new binaries claiming side by side during a rollout would
        # need the Lease to serialise both; Recreate avoids the overlap.
        self.assertIn("type: Recreate", output)

    def test_role_allows_lease_operations_for_the_worker(self):
        output = render("templates/claim-lock-rbac.yaml")
        self.assertIn("kind: ServiceAccount\nmetadata:\n  name: test-parsing-worker", output)
        self.assertIn('apiGroups: ["coordination.k8s.io"]', output)
        self.assertIn('resources: ["leases"]', output)
        self.assertIn('verbs: ["get", "create", "update"]', output)
        self.assertIn("kind: RoleBinding", output)
        self.assertIn("    name: test-parsing-worker\n    namespace: default", output)


if __name__ == "__main__":
    unittest.main()
