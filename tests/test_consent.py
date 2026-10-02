import copy
import http.client
import json
import threading
import unittest
from http.server import ThreadingHTTPServer

from privacare.consent import evaluate_consent_request
from privacare.server import Handler
from privacare.service import Service


def _consent(**overrides):
    consent = {
        "consent_id": "c1",
        "subject_id": "s1",
        "purposes": ["treatment"],
        "data_categories": ["clinical"],
        "recipients": ["hospital-a"],
        "valid_from": "2026-01-01T00:00:00Z",
        "valid_until": "2026-12-31T23:59:59Z",
        "status": "active",
    }
    consent.update(overrides)
    return consent


def _access(**overrides):
    access = {
        "subject_id": "s1",
        "purpose": "treatment",
        "data_category": "clinical",
        "recipient": "hospital-a",
        "requested_at": "2026-06-15T10:30:00Z",
    }
    access.update(overrides)
    return access


def _payload(consents=None, accesses=None):
    return {
        "consents": consents if consents is not None else [_consent()],
        "accesses": accesses if accesses is not None else [_access()],
    }


class EvaluateConsentServiceTest(unittest.TestCase):
    def setUp(self):
        self.service = Service()

    def evaluate(self, payload):
        return self.service.evaluate_consent(payload)

    def test_granted(self):
        results = self.evaluate(_payload())
        self.assertEqual(
            results,
            [
                {
                    "index": 0,
                    "allowed": True,
                    "reason": "consent_granted",
                    "consent_id": "c1",
                }
            ],
        )

    def test_denied_without_consent_id(self):
        results = self.evaluate(_payload(accesses=[_access(purpose="research")]))
        self.assertEqual(
            results,
            [{"index": 0, "allowed": False, "reason": "no_matching_consent"}],
        )

    def test_revoked_consent_never_grants(self):
        results = self.evaluate(_payload(consents=[_consent(status="revoked")]))
        self.assertFalse(results[0]["allowed"])
        self.assertEqual(results[0]["reason"], "no_matching_consent")

    def test_each_dimension_must_match(self):
        cases = [
            _access(subject_id="other"),
            _access(purpose="marketing"),
            _access(data_category="contact"),
            _access(recipient="hospital-b"),
            _access(requested_at="2025-12-31T23:59:59Z"),
            _access(requested_at="2027-01-01T00:00:00Z"),
        ]
        results = self.evaluate(_payload(accesses=cases))
        self.assertEqual([r["allowed"] for r in results], [False] * len(cases))
        self.assertEqual([r["index"] for r in results], list(range(len(cases))))

    def test_requested_at_lower_bound_inclusive_upper_exclusive(self):
        accesses = [
            _access(requested_at="2026-01-01T00:00:00Z"),
            _access(requested_at="2026-12-31T23:59:59Z"),
        ]
        results = self.evaluate(_payload(accesses=accesses))
        self.assertEqual([r["allowed"] for r in results], [True, False])

    def test_timezone_offsets_compare_by_instant(self):
        accesses = [
            _access(requested_at="2026-01-01T08:00:00+08:00"),  # == valid_from
            _access(requested_at="2025-12-31T17:00:00-07:00"),  # == valid_from
        ]
        results = self.evaluate(_payload(accesses=accesses))
        self.assertEqual([r["allowed"] for r in results], [True, True])

    def test_latest_valid_from_wins(self):
        consents = [
            _consent(consent_id="older", valid_from="2026-01-01T00:00:00Z"),
            _consent(consent_id="newer", valid_from="2026-03-01T00:00:00Z"),
        ]
        results = self.evaluate(_payload(consents=consents))
        self.assertEqual(results[0]["consent_id"], "newer")

    def test_tie_breaks_on_smallest_consent_id(self):
        consents = [
            _consent(consent_id="c-z"),
            _consent(consent_id="c-a"),
            _consent(consent_id="c-m"),
        ]
        results = self.evaluate(_payload(consents=consents))
        self.assertEqual(results[0]["consent_id"], "c-a")

    def test_revoked_consent_not_selected_over_active(self):
        consents = [
            _consent(consent_id="revoked-new", valid_from="2026-06-01T00:00:00Z", status="revoked"),
            _consent(consent_id="active-old", valid_from="2026-01-01T00:00:00Z"),
        ]
        results = self.evaluate(_payload(consents=consents))
        self.assertEqual(results[0]["consent_id"], "active-old")

    def test_results_follow_access_order(self):
        accesses = [
            _access(purpose="unknown"),
            _access(),
            _access(recipient="nobody"),
        ]
        results = self.evaluate(_payload(accesses=accesses))
        self.assertEqual(
            [(r["index"], r["allowed"]) for r in results],
            [(0, False), (1, True), (2, False)],
        )

    def test_input_not_mutated_and_deterministic(self):
        payload = _payload(
            consents=[_consent(), _consent(consent_id="c2", valid_from="2026-02-01T00:00:00Z")],
            accesses=[_access(), _access(purpose="research")],
        )
        snapshot = copy.deepcopy(payload)
        first = self.evaluate(payload)
        second = self.evaluate(payload)
        self.assertEqual(payload, snapshot)
        self.assertEqual(first, second)

    def test_response_does_not_echo_input_values(self):
        payload = _payload()
        results = self.evaluate(payload)
        blob = json.dumps(results, ensure_ascii=False)
        for secret in ("s1", "treatment", "hospital-a", "2026-06-15"):
            self.assertNotIn(secret, blob)


class EvaluateConsentValidationTest(unittest.TestCase):
    def setUp(self):
        self.service = Service()

    def test_invalid_request_shapes(self):
        from privacare.classifier import InvalidRequest

        for payload in (
            [],
            {},
            {"consents": []},
            {"accesses": []},
            {"consents": [], "accesses": []},
            {"consents": [_consent()]},
            {"accesses": [_access()]},
            {"consents": "x", "accesses": [_access()]},
            {"consents": [_consent()], "accesses": {}},
        ):
            with self.subTest(payload=payload):
                with self.assertRaises(InvalidRequest):
                    self.service.evaluate_consent(payload)

    def test_invalid_consent_cases(self):
        from privacare.consent import InvalidConsent

        base = _consent()
        bad_consents = []
        for field in base:
            broken = _consent()
            del broken[field]
            bad_consents.append(broken)
        bad_consents += [
            _consent(consent_id=""),
            _consent(subject_id=""),
            _consent(purposes=[]),
            _consent(purposes=["a", "a"]),
            _consent(purposes="treatment"),
            _consent(data_categories=[]),
            _consent(data_categories=["clinical", "clinical"]),
            _consent(data_categories=["nope"]),
            _consent(recipients=[]),
            _consent(recipients=["r", "r"]),
            _consent(status="pending"),
            _consent(valid_from="2026-01-01"),
            _consent(valid_from="2026-01-01 00:00:00+00:00"),
            _consent(valid_from="2026-13-01T00:00:00Z"),
            _consent(valid_until="not-a-time"),
            _consent(valid_until="2026-01-01T00:00:00Z"),  # equal to valid_from
            _consent(valid_from="2026-06-01T00:00:00Z", valid_until="2026-01-01T00:00:00Z"),
        ]
        for consent in bad_consents:
            with self.subTest(consent=consent):
                with self.assertRaises(InvalidConsent):
                    self.service.evaluate_consent(_payload(consents=[consent]))

    def test_duplicate_consent_id(self):
        from privacare.consent import InvalidConsent

        with self.assertRaises(InvalidConsent):
            self.service.evaluate_consent(
                _payload(consents=[_consent(), _consent(subject_id="s2")])
            )

    def test_invalid_access_cases(self):
        from privacare.consent import InvalidAccess

        base = _access()
        bad_accesses = []
        for field in base:
            broken = _access()
            del broken[field]
            bad_accesses.append(broken)
        bad_accesses += [
            _access(data_category="nope"),
            _access(data_category=["clinical"]),
            _access(requested_at="2026-06-15"),
            _access(requested_at="2026-06-15T10:30:00"),
            _access(requested_at="2026-06-15T25:30:00Z"),
            "not-an-object",
        ]
        for access in bad_accesses:
            with self.subTest(access=access):
                with self.assertRaises(InvalidAccess):
                    self.service.evaluate_consent(_payload(accesses=[access]))

    def test_no_partial_results_on_any_failure(self):
        from privacare.consent import InvalidAccess, InvalidConsent

        with self.assertRaises(InvalidConsent):
            self.service.evaluate_consent(
                _payload(consents=[_consent(), _consent(consent_id="c2", status="bad")])
            )
        with self.assertRaises(InvalidAccess):
            self.service.evaluate_consent(
                _payload(accesses=[_access(), _access(data_category="bad")])
            )


class EvaluateConsentHttpTest(unittest.TestCase):
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

    def post(self, payload, content_type="application/json"):
        body = payload if isinstance(payload, (str, bytes)) else json.dumps(payload)
        return self.request("POST", "/v1/consent/evaluate", body=body, content_type=content_type)

    def test_happy_path(self):
        status, payload = self.post(_payload())
        self.assertEqual(status, 200)
        self.assertEqual(
            payload["results"],
            [
                {
                    "index": 0,
                    "allowed": True,
                    "reason": "consent_granted",
                    "consent_id": "c1",
                }
            ],
        )

    def test_error_codes(self):
        cases = [
            ({"accesses": [_access()]}, "invalid_request"),
            (_payload(consents=[_consent(status="bad")]), "invalid_consent"),
            (_payload(accesses=[_access(requested_at="x")]), "invalid_access"),
        ]
        for body, code in cases:
            with self.subTest(code=code):
                status, payload = self.post(body)
                self.assertEqual(status, 422)
                self.assertEqual(payload["error"]["code"], code)

    def test_unsupported_media_type(self):
        status, payload = self.post(_payload(), content_type="text/plain")
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

    def test_unknown_path_still_404(self):
        status, payload = self.request("POST", "/v1/consent")
        self.assertEqual(status, 404)
        self.assertEqual(payload["error"]["code"], "not_found")


if __name__ == "__main__":
    unittest.main()
