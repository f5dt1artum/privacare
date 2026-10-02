import json
import unittest

from privacare import __version__
from privacare.service import Service


class HealthSmokeTest(unittest.TestCase):
    def test_health_reports_ok(self) -> None:
        payload = Service().health()
        self.assertEqual(payload["status"], "ok")
        self.assertEqual(payload["service"], "privacare")
        self.assertEqual(payload["version"], __version__)
        json.dumps(payload, sort_keys=True)


if __name__ == "__main__":
    unittest.main()
