"""ClickHouse version pins must not drift apart (#392).

Until 0.8.0 the chart shipped 24.8 while CI and docker-compose tested 24.12, so
the query smoke test never ran against the version users actually install.
The chart now ships the LTS floor, CI runs the smoke test against both the
floor and the development version, and these tests keep the pins in sync:

- the chart's default image is in the CI matrix (as "floor"),
- docker-compose's image is in the CI matrix (as "dev"),
- every example values file installs the chart's image,
- every pin carries a digest.

Run with python3 -m unittest discover -s deploy/helm/tests -v.
"""

from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[3]
VALUES = ROOT / "deploy/helm/bomhort/values.yaml"
CI = ROOT / ".github/workflows/ci.yml"
COMPOSE = ROOT / "docker-compose.yml"
EXAMPLES = sorted((ROOT / "examples").rglob("values*.yaml"))

IMAGE = re.compile(r"(?:docker\.io/)?clickhouse/clickhouse-server:\S+")


def normalise(image):
    """docker.io/ is implied for Docker Hub images; compare without it."""
    return image.removeprefix("docker.io/")


def images_in(path):
    return [normalise(m) for m in IMAGE.findall(path.read_text())]


def chart_image():
    match = re.search(r"containerImage:\s*(\S+)", VALUES.read_text())
    assert match, "clickhouse containerImage not found in values.yaml"
    return normalise(match.group(1))


def ci_matrix():
    """name -> image of the query-smoke ClickHouse matrix."""
    text = CI.read_text()
    entries = re.findall(
        r"-\s*name:\s*(\S+)\s*\n\s*image:\s*(\S*clickhouse-server\S*)", text
    )
    return {name: normalise(image) for name, image in entries}


class ClickHouseVersionTest(unittest.TestCase):
    def test_ci_matrix_has_floor_and_dev(self):
        self.assertEqual(set(ci_matrix()), {"floor", "dev"})

    def test_chart_ships_the_ci_floor(self):
        self.assertEqual(chart_image(), ci_matrix()["floor"])

    def test_compose_runs_the_ci_dev_version(self):
        self.assertEqual(images_in(COMPOSE), [ci_matrix()["dev"]])

    def test_ci_uses_only_matrix_images(self):
        """The migration runner must use the matrix image, not a literal."""
        matrix = set(ci_matrix().values())
        self.assertEqual(set(images_in(CI)), matrix)

    def test_examples_install_the_chart_image(self):
        checked = 0
        for path in EXAMPLES:
            for image in images_in(path):
                checked += 1
                with self.subTest(path=str(path.relative_to(ROOT))):
                    self.assertEqual(image, chart_image())
        self.assertGreater(checked, 0, "no example pins a ClickHouse image")

    def test_every_pin_has_a_digest(self):
        for path in [VALUES, CI, COMPOSE, *EXAMPLES]:
            for image in images_in(path):
                with self.subTest(path=str(path.relative_to(ROOT)), image=image):
                    self.assertRegex(image, r"@sha256:[0-9a-f]{64}$")


if __name__ == "__main__":
    unittest.main()
