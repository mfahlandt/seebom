"""ClickHouse version pins must not drift apart (#392) and the per-query
limits reach the ClickHouseInstallation (#344-I).

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
IMAGE = re.compile(r"clickhouse/clickhouse-server:(\d+\.\d+)")


def render(values=None, args=()):
    with tempfile.TemporaryDirectory() as directory:
        values_file = Path(directory) / "values.json"
        values_file.write_text(json.dumps(values or {}))
        result = subprocess.run(
            ["helm", "template", "test", str(CHART), "-f", str(values_file), *args],
            cwd=ROOT, text=True, capture_output=True, check=False,
        )
    assert result.returncode == 0, result.stderr
    return result.stdout


def versions_in(path):
    return set(IMAGE.findall((ROOT / path).read_text()))


class ClickHouseVersionTest(unittest.TestCase):
    def test_chart_compose_and_ci_pin_the_same_version(self):
        chart = versions_in("deploy/helm/bomhort/values.yaml")
        self.assertEqual(len(chart), 1, chart)
        for path in ("docker-compose.yml", ".github/workflows/ci.yml",
                     "examples/kind/values-kind.yaml",
                     "examples/kubernetes/values-minimal.yaml",
                     "examples/kubernetes/values-production.yaml",
                     "examples/kubernetes/values-cncf.yaml"):
            with self.subTest(path=path):
                found = versions_in(path)
                self.assertTrue(found, f"{path} pins no ClickHouse image")
                self.assertEqual(found, chart, f"{path} pins {found}, chart pins {chart}")

    def test_installation_renders_the_chart_version(self):
        (chart,) = versions_in("deploy/helm/bomhort/values.yaml")
        self.assertIn(f"image: docker.io/clickhouse/clickhouse-server:{chart}", render())


class QueryLimitsTest(unittest.TestCase):
    def installation(self, rendered):
        match = re.search(
            r"# Source: bomhort/templates/clickhouse-installation\.yaml\n(.*?)(?=\n---|\Z)",
            rendered, re.DOTALL,
        )
        self.assertIsNotNone(match)
        return match.group(1)

    def test_defaults_limit_time_and_memory_for_the_default_user(self):
        chi = self.installation(render())
        self.assertIn("default/max_execution_time: 30", chi)
        self.assertIn("default/max_memory_usage: 536870912", chi)
        self.assertNotIn("max_threads", chi)
        self.assertNotIn("/profile:", chi)

    def test_custom_user_gets_its_own_profile(self):
        chi = self.installation(render({"clickhouse": {"user": "bomhort",
                                                       "installation": {"profile": {"maxThreads": 4}}}}))
        self.assertIn("bomhort/profile: bomhort", chi)
        self.assertIn("bomhort/max_execution_time: 30", chi)
        self.assertIn("bomhort/max_threads: 4", chi)
        self.assertNotIn("default/max_", chi)

    def test_zero_disables_all_limits(self):
        chi = self.installation(render({"clickhouse": {"installation": {"profile": {
            "maxExecutionTime": 0, "maxMemoryUsage": 0, "maxThreads": 0}}}}))
        self.assertNotIn("profiles:", chi)

    def test_compose_profile_matches_chart_defaults(self):
        xml = (ROOT / "db/clickhouse/users.d/query-limits.xml").read_text()
        self.assertIn("<max_execution_time>30</max_execution_time>", xml)
        self.assertIn("<max_memory_usage>536870912</max_memory_usage>", xml)
        self.assertIn("db/clickhouse/users.d/query-limits.xml:/etc/clickhouse-server/users.d/",
                      (ROOT / "docker-compose.yml").read_text())


if __name__ == "__main__":
    unittest.main()
