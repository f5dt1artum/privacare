import copy
import http.client
import json
import threading
import unittest
from http.server import ThreadingHTTPServer

from privacare.server import Handler


class HttpTestBase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.port = cls.httpd.server_address[1]
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls.thread.join()

    def request(self, method, path, body=None, content_type=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        headers = {}
        if content_type is not None:
            headers["Content-Type"] = content_type
        conn.request(method, path, body=body, headers=headers)
        resp = conn.getresponse()
        raw = resp.read()
        conn.close()
        return resp.status, json.loads(raw)


def make_consent(**overrides):
    consent = {
        "consent_id": "c-1",
        "subject_id": "subj-1",
        "purposes": ["treatment"],
        "data_categories": ["clinical"],
        "recipients": ["hospital-a"],
        "valid_from": "2026-01-01T00:00:00Z",
        "valid_until": "2026-12-31T23:59:59Z",
        "status": "active",
    }
    consent.update(overrides)
    return consent


def make_access(**overrides):
    access = {
        "subject_id": "subj-1",
        "purpose": "treatment",
        "data_category": "clinical",
        "recipient": "hospital-a",
        "requested_at": "2026-06-01T12:00:00Z",
    }
    access.update(overrides)
    return access


class ConsentEvaluateHttpTest(HttpTestBase):
    def post(self, payload, content_type="application/json"):
        body = payload if isinstance(payload, (str, bytes)) else json.dumps(payload)
        return self.request("POST", "/v1/consent/evaluate", body=body, content_type=content_type)

    def test_grant_and_deny(self):
        status, payload = self.post(
            {
                "consents": [make_consent()],
                "accesses": [
                    make_access(),
                    make_access(purpose="research"),
                    make_access(subject_id="subj-2"),
                    make_access(data_category="contact"),
                    make_access(recipient="hospital-b"),
                ],
            }
        )
        self.assertEqual(status, 200)
        results = payload["results"]
        self.assertEqual([r["index"] for r in results], [0, 1, 2, 3, 4])
        self.assertEqual(
            results[0],
            {"index": 0, "allowed": True, "reason": "consent_granted", "consent_id": "c-1"},
        )
        for result in results[1:]:
            self.assertEqual(result["allowed"], False)
            self.assertEqual(result["reason"], "no_matching_consent")
            self.assertNotIn("consent_id", result)

    def test_revoked_consent_does_not_authorize(self):
        status, payload = self.post(
            {"consents": [make_consent(status="revoked")], "accesses": [make_access()]}
        )
        self.assertEqual(status, 200)
        self.assertEqual(payload["results"][0]["reason"], "no_matching_consent")

    def test_time_window_boundaries(self):
        # requested_at == valid_from is allowed; == valid_until is not.
        status, payload = self.post(
            {
                "consents": [make_consent()],
                "accesses": [
                    make_access(requested_at="2026-01-01T00:00:00Z"),
                    make_access(requested_at="2025-12-31T23:59:59Z"),
                    make_access(requested_at="2026-12-31T23:59:58Z"),
                    make_access(requested_at="2026-12-31T23:59:59Z"),
                ],
            }
        )
        self.assertEqual(status, 200)
        self.assertEqual(
            [r["allowed"] for r in payload["results"]],
            [True, False, True, False],
        )

    def test_timezone_offsets_compare_by_instant(self):
        status, payload = self.post(
            {
                "consents": [make_consent(valid_from="2026-01-01T08:00:00+08:00")],
                "accesses": [make_access(requested_at="2026-01-01T00:00:00Z")],
            }
        )
        self.assertEqual(status, 200)
        self.assertEqual(payload["results"][0]["allowed"], True)

    def test_latest_valid_from_wins(self):
        status, payload = self.post(
            {
                "consents": [
                    make_consent(consent_id="c-old", valid_from="2026-01-01T00:00:00Z"),
                    make_consent(consent_id="c-new", valid_from="2026-03-01T00:00:00Z"),
                ],
                "accesses": [make_access()],
            }
        )
        self.assertEqual(status, 200)
        self.assertEqual(payload["results"][0]["consent_id"], "c-new")

    def test_tie_breaks_on_smallest_consent_id(self):
        status, payload = self.post(
            {
                "consents": [
                    make_consent(consent_id="c-b"),
                    make_consent(consent_id="c-a"),
                ],
                "accesses": [make_access()],
            }
        )
        self.assertEqual(status, 200)
        self.assertEqual(payload["results"][0]["consent_id"], "c-a")

    def test_no_echo_and_no_mutation_and_deterministic(self):
        payload = {
            "consents": [make_consent(), make_consent(consent_id="c-2", status="revoked")],
            "accesses": [make_access(), make_access(purpose="research")],
        }
        snapshot = copy.deepcopy(payload)
        status, first = self.post(payload)
        self.assertEqual(status, 200)
        self.assertEqual(payload, snapshot)
        status, second = self.post(payload)
        self.assertEqual(status, 200)
        self.assertEqual(first, second)
        # 响应不回 echo 输入的主体、用途或接收方取值
        body = json.dumps(first)
        self.assertNotIn("subj-1", body)
        self.assertNotIn("hospital-a", body)
        self.assertNotIn("treatment", body)

    def test_invalid_request(self):
        for body in (
            "[]",
            "{}",
            '{"consents": []}',
            '{"accesses": []}',
            '{"consents": [], "accesses": [{}]}',
            '{"consents": [{}], "accesses": []}',
            '{"consents": {}, "accesses": [{}]}',
        ):
            with self.subTest(body=body):
                status, payload = self.post(body)
                self.assertEqual(status, 422)
                self.assertEqual(payload["error"]["code"], "invalid_request")

    def test_invalid_consent(self):
        base = make_consent()
        cases = []
        for field in (
            "consent_id",
            "subject_id",
            "purposes",
            "data_categories",
            "recipients",
            "valid_from",
            "valid_until",
            "status",
        ):
            broken = {k: v for k, v in base.items() if k != field}
            cases.append(broken)
        cases += [
            "not-an-object",
            make_consent(consent_id=""),
            make_consent(subject_id=""),
            make_consent(purposes=[]),
            make_consent(purposes=["treatment", "treatment"]),
            make_consent(data_categories=[]),
            make_consent(data_categories=["clinical", "clinical"]),
            make_consent(data_categories=["unknown"]),
            make_consent(recipients=[]),
            make_consent(recipients=["a", "a"]),
            make_consent(status="pending"),
            make_consent(valid_from="2026-01-01"),
            make_consent(valid_from="2026-01-01 00:00:00Z"),
            make_consent(valid_from="2026-01-01T00:00:00"),
            make_consent(valid_until="not-a-time"),
            make_consent(valid_until="2026-01-01T00:00:00Z"),  # equal to valid_from
            make_consent(valid_from="2026-06-01T00:00:00Z", valid_until="2026-01-01T00:00:00Z"),
        ]
        for consent in cases:
            with self.subTest(consent=consent):
                status, payload = self.post(
                    {"consents": [consent], "accesses": [make_access()]}
                )
                self.assertEqual(status, 422)
                self.assertEqual(payload["error"]["code"], "invalid_consent")

    def test_duplicate_consent_id(self):
        status, payload = self.post(
            {
                "consents": [make_consent(), make_consent(subject_id="subj-2")],
                "accesses": [make_access()],
            }
        )
        self.assertEqual(status, 422)
        self.assertEqual(payload["error"]["code"], "invalid_consent")

    def test_invalid_access(self):
        base = make_access()
        cases = []
        for field in ("subject_id", "purpose", "data_category", "recipient", "requested_at"):
            broken = {k: v for k, v in base.items() if k != field}
            cases.append(broken)
        cases += [
            "not-an-object",
            make_access(subject_id=""),
            make_access(data_category="unknown"),
            make_access(requested_at="2026-06-01T12:00:00"),
            make_access(requested_at="not-a-time"),
        ]
        for access in cases:
            with self.subTest(access=access):
                status, payload = self.post(
                    {"consents": [make_consent()], "accesses": [access]}
                )
                self.assertEqual(status, 422)
                self.assertEqual(payload["error"]["code"], "invalid_access")

    def test_no_partial_results_on_any_failure(self):
        status, payload = self.post(
            {
                "consents": [make_consent()],
                "accesses": [make_access(), make_access(data_category="unknown")],
            }
        )
        self.assertEqual(status, 422)
        self.assertNotIn("results", payload)

    def test_unsupported_media_type(self):
        status, payload = self.post(
            {"consents": [make_consent()], "accesses": [make_access()]},
            content_type="text/plain",
        )
        self.assertEqual(status, 415)
        self.assertEqual(payload["error"]["code"], "unsupported_media_type")

    def test_invalid_json(self):
        status, payload = self.post("{not json")
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"]["code"], "invalid_json")

    def test_method_not_allowed(self):
        for method in ("GET", "PUT", "DELETE", "PATCH"):
            with self.subTest(method=method):
                status, payload = self.request(method, "/v1/consent/evaluate")
                self.assertEqual(status, 405)
                self.assertEqual(payload["error"]["code"], "method_not_allowed")

    def test_unknown_path_404(self):
        status, payload = self.request("POST", "/v1/consent")
        self.assertEqual(status, 404)
        self.assertEqual(payload["error"]["code"], "not_found")


if __name__ == "__main__":
    unittest.main()
