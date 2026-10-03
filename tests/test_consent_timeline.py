import copy
import http.client
import json
import threading
import unittest
from http.server import ThreadingHTTPServer

from privacare.server import Handler
from privacare.service import Service


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


def make_grant(**overrides):
    event = {
        "event_id": "e-1",
        "consent_id": "c-1",
        "version": 1,
        "occurred_at": "2026-01-01T00:00:00Z",
        "type": "grant",
        "subject_id": "subj-1",
        "purposes": ["treatment"],
        "data_categories": ["clinical"],
        "recipients": ["hospital-a"],
        "valid_from": "2026-01-01T00:00:00Z",
        "valid_until": "2026-12-31T23:59:59Z",
    }
    event.update(overrides)
    return event


def make_amend(**overrides):
    event = {
        "event_id": "e-2",
        "consent_id": "c-1",
        "version": 2,
        "occurred_at": "2026-03-01T00:00:00Z",
        "type": "amend",
        "purposes": ["research"],
        "data_categories": ["contact"],
        "recipients": ["lab-b"],
        "valid_from": "2026-03-01T00:00:00Z",
        "valid_until": "2026-09-30T23:59:59Z",
    }
    event.update(overrides)
    return event


def make_revoke(**overrides):
    event = {
        "event_id": "e-3",
        "consent_id": "c-1",
        "version": 3,
        "occurred_at": "2026-06-01T00:00:00Z",
        "type": "revoke",
    }
    event.update(overrides)
    return event


def make_query(**overrides):
    query = {"consent_id": "c-1", "as_of": "2026-06-01T12:00:00Z"}
    query.update(overrides)
    return query


class ConsentTimelineHttpTest(HttpTestBase):
    def post(self, payload, content_type="application/json"):
        body = payload if isinstance(payload, (str, bytes)) else json.dumps(payload)
        return self.request("POST", "/v1/consent/timeline", body=body, content_type=content_type)

    def test_grant_active_pending_expired(self):
        status, payload = self.post(
            {
                "events": [make_grant()],
                "queries": [
                    make_query(as_of="2026-06-01T12:00:00Z"),
                    make_query(as_of="2025-12-31T23:59:59Z"),
                    make_query(as_of="2026-12-31T23:59:59Z"),
                    make_query(as_of="2027-01-01T00:00:00Z"),
                ],
            }
        )
        self.assertEqual(status, 200)
        results = payload["results"]
        self.assertEqual([r["status"] for r in results], ["active", "not_found", "expired", "expired"])
        active = results[0]
        self.assertEqual(active["version"], 1)
        self.assertEqual(active["last_event_id"], "e-1")
        self.assertEqual(
            active["snapshot"],
            {
                "consent_id": "c-1",
                "subject_id": "subj-1",
                "purposes": ["treatment"],
                "data_categories": ["clinical"],
                "recipients": ["hospital-a"],
                "valid_from": "2026-01-01T00:00:00Z",
                "valid_until": "2026-12-31T23:59:59Z",
            },
        )
        # 尚未授予：无快照、无版本
        self.assertEqual(results[1], {"consent_id": "c-1", "status": "not_found"})

    def test_pending_between_event_and_valid_from(self):
        status, payload = self.post(
            {
                "events": [make_grant(valid_from="2026-02-01T00:00:00Z")],
                "queries": [make_query(as_of="2026-01-15T00:00:00Z")],
            }
        )
        self.assertEqual(status, 200)
        self.assertEqual(payload["results"][0]["status"], "pending")

    def test_amend_replaces_scope_and_keeps_subject(self):
        status, payload = self.post(
            {
                "events": [make_grant(), make_amend()],
                "queries": [make_query(as_of="2026-04-01T00:00:00Z")],
            }
        )
        self.assertEqual(status, 200)
        result = payload["results"][0]
        self.assertEqual(result["status"], "active")
        self.assertEqual(result["version"], 2)
        self.assertEqual(result["last_event_id"], "e-2")
        self.assertEqual(
            result["snapshot"],
            {
                "consent_id": "c-1",
                "subject_id": "subj-1",
                "purposes": ["research"],
                "data_categories": ["contact"],
                "recipients": ["lab-b"],
                "valid_from": "2026-03-01T00:00:00Z",
                "valid_until": "2026-09-30T23:59:59Z",
            },
        )

    def test_revoke_wins_and_keeps_snapshot(self):
        status, payload = self.post(
            {
                "events": [make_grant(), make_amend(), make_revoke()],
                "queries": [
                    make_query(as_of="2026-06-01T00:00:00Z"),
                    make_query(as_of="2026-05-31T23:59:59Z"),
                ],
            }
        )
        self.assertEqual(status, 200)
        revoked, before = payload["results"]
        self.assertEqual(revoked["status"], "revoked")
        self.assertEqual(revoked["version"], 3)
        self.assertEqual(revoked["last_event_id"], "e-3")
        self.assertEqual(revoked["snapshot"]["purposes"], ["research"])
        self.assertEqual(before["status"], "active")
        self.assertEqual(before["version"], 2)

    def test_unknown_consent_is_not_found(self):
        status, payload = self.post(
            {"events": [make_grant()], "queries": [make_query(consent_id="c-other")]}
        )
        self.assertEqual(status, 200)
        self.assertEqual(payload["results"], [{"consent_id": "c-other", "status": "not_found"}])

    def test_event_order_does_not_matter(self):
        events = [make_revoke(), make_amend(), make_grant()]
        queries = [make_query(as_of="2026-06-02T00:00:00Z"), make_query(as_of="2026-04-01T00:00:00Z")]
        status, first = self.post({"events": events, "queries": queries})
        self.assertEqual(status, 200)
        status, second = self.post({"events": list(reversed(events)), "queries": queries})
        self.assertEqual(status, 200)
        self.assertEqual(first, second)
        self.assertEqual([r["status"] for r in first["results"]], ["revoked", "active"])

    def test_multiple_consents_and_query_order(self):
        other = make_grant(
            event_id="e-9",
            consent_id="c-2",
            subject_id="subj-2",
            occurred_at="2026-05-01T00:00:00Z",
            valid_from="2026-05-01T00:00:00Z",
        )
        status, payload = self.post(
            {
                "events": [other, make_grant()],
                "queries": [
                    make_query(consent_id="c-2", as_of="2026-06-01T00:00:00Z"),
                    make_query(consent_id="c-1", as_of="2026-06-01T00:00:00Z"),
                ],
            }
        )
        self.assertEqual(status, 200)
        results = payload["results"]
        self.assertEqual([r["consent_id"] for r in results], ["c-2", "c-1"])
        self.assertEqual(results[0]["snapshot"]["subject_id"], "subj-2")
        self.assertEqual(results[1]["snapshot"]["subject_id"], "subj-1")

    def test_timezone_offsets_compare_by_instant(self):
        status, payload = self.post(
            {
                "events": [make_grant(occurred_at="2026-01-01T08:00:00+08:00")],
                "queries": [
                    make_query(as_of="2026-01-01T00:00:00Z"),
                    make_query(as_of="2025-12-31T23:59:59Z"),
                ],
            }
        )
        self.assertEqual(status, 200)
        self.assertEqual(
            [r["status"] for r in payload["results"]], ["active", "not_found"]
        )

    def test_no_mutation_and_deterministic(self):
        payload = {
            "events": [make_grant(), make_amend(), make_revoke()],
            "queries": [make_query(as_of="2026-06-02T00:00:00Z")],
        }
        snapshot = copy.deepcopy(payload)
        status, first = self.post(payload)
        self.assertEqual(status, 200)
        self.assertEqual(payload, snapshot)
        status, second = self.post(payload)
        self.assertEqual(status, 200)
        self.assertEqual(first, second)

    def test_invalid_request(self):
        for body in (
            "[]",
            "{}",
            '{"events": []}',
            '{"queries": []}',
            '{"events": [], "queries": [{}]}',
            '{"events": [{}], "queries": []}',
            '{"events": {}, "queries": [{}]}',
            '{"events": [{}], "queries": {}}',
        ):
            with self.subTest(body=body):
                status, payload = self.post(body)
                self.assertEqual(status, 422)
                self.assertEqual(payload["error"]["code"], "invalid_request")

    def test_invalid_event_fields(self):
        base = make_grant()
        cases = []
        for field in ("event_id", "consent_id", "version", "occurred_at", "type"):
            broken = {k: v for k, v in base.items() if k != field}
            cases.append(broken)
        cases += [
            "not-an-object",
            make_grant(event_id=""),
            make_grant(consent_id=""),
            make_grant(version=0),
            make_grant(version=-1),
            make_grant(version=1.5),
            make_grant(version=True),
            make_grant(version="1"),
            make_grant(occurred_at="2026-01-01"),
            make_grant(occurred_at="2026-01-01T00:00:00"),
            make_grant(occurred_at="not-a-time"),
            make_grant(type="extend"),
            make_grant(subject_id=""),
            make_grant(purposes=[]),
            make_grant(purposes=["a", "a"]),
            make_grant(data_categories=[]),
            make_grant(data_categories=["unknown"]),
            make_grant(recipients=[]),
            make_grant(recipients=["a", "a"]),
            make_grant(valid_from="2026-01-01"),
            make_grant(valid_until="2026-01-01T00:00:00Z"),  # equal to valid_from
            make_grant(valid_from="2026-06-01T00:00:00Z", valid_until="2026-01-01T00:00:00Z"),
        ]
        for event in cases:
            with self.subTest(event=event):
                status, payload = self.post(
                    {"events": [event], "queries": [make_query()]}
                )
                self.assertEqual(status, 422)
                self.assertEqual(payload["error"]["code"], "invalid_consent_event")

    def test_invalid_event_type_specific_fields(self):
        cases = [
            make_amend(subject_id="subj-1"),
            {k: v for k, v in make_amend().items() if k != "purposes"},
            {k: v for k, v in make_amend().items() if k != "valid_until"},
            make_revoke(subject_id="subj-1"),
            make_revoke(purposes=["treatment"]),
            make_revoke(data_categories=["clinical"]),
            make_revoke(recipients=["hospital-a"]),
            make_revoke(valid_from="2026-01-01T00:00:00Z"),
            make_revoke(valid_until="2026-12-31T23:59:59Z"),
        ]
        for event in cases:
            with self.subTest(event=event):
                status, payload = self.post(
                    {
                        "events": [make_grant(), event],
                        "queries": [make_query()],
                    }
                )
                self.assertEqual(status, 422)
                self.assertEqual(payload["error"]["code"], "invalid_consent_event")

    def test_invalid_event_sequence(self):
        sequences = [
            [make_grant(), make_grant(event_id="e-2", version=2, occurred_at="2026-02-01T00:00:00Z")],
            [make_amend(version=1)],
            [make_revoke(version=1)],
            [make_grant(version=2)],
            [make_grant(), make_amend(version=3)],
            [make_grant(), make_amend(version=2), make_amend(event_id="e-3", version=2)],
            [make_grant(), make_amend(occurred_at="2025-12-31T23:59:59Z")],
            [make_grant(), make_revoke(version=2), make_amend(event_id="e-3", version=3, occurred_at="2026-07-01T00:00:00Z")],
            [make_grant(), make_revoke(version=2), make_revoke(event_id="e-3", version=3, occurred_at="2026-07-01T00:00:00Z")],
        ]
        for events in sequences:
            with self.subTest(events=events):
                status, payload = self.post({"events": events, "queries": [make_query()]})
                self.assertEqual(status, 422)
                self.assertEqual(payload["error"]["code"], "invalid_consent_event")

    def test_duplicate_event_id(self):
        status, payload = self.post(
            {
                "events": [
                    make_grant(),
                    make_grant(event_id="e-1", consent_id="c-2"),
                ],
                "queries": [make_query()],
            }
        )
        self.assertEqual(status, 422)
        self.assertEqual(payload["error"]["code"], "invalid_consent_event")

    def test_invalid_query(self):
        base = make_query()
        cases = []
        for field in ("consent_id", "as_of"):
            broken = {k: v for k, v in base.items() if k != field}
            cases.append(broken)
        cases += [
            "not-an-object",
            make_query(consent_id=""),
            make_query(as_of="2026-06-01"),
            make_query(as_of="2026-06-01T12:00:00"),
            make_query(as_of="not-a-time"),
        ]
        for query in cases:
            with self.subTest(query=query):
                status, payload = self.post(
                    {"events": [make_grant()], "queries": [query]}
                )
                self.assertEqual(status, 422)
                self.assertEqual(payload["error"]["code"], "invalid_query")

    def test_no_partial_results_on_any_failure(self):
        status, payload = self.post(
            {
                "events": [make_grant()],
                "queries": [make_query(), make_query(as_of="bad")],
            }
        )
        self.assertEqual(status, 422)
        self.assertNotIn("results", payload)

    def test_unsupported_media_type(self):
        status, payload = self.post(
            {"events": [make_grant()], "queries": [make_query()]},
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
                status, payload = self.request(method, "/v1/consent/timeline")
                self.assertEqual(status, 405)
                self.assertEqual(payload["error"]["code"], "method_not_allowed")

    def test_unknown_path_404(self):
        status, payload = self.request("POST", "/v1/consent/timeline/extra")
        self.assertEqual(status, 404)
        self.assertEqual(payload["error"]["code"], "not_found")


class ConsentTimelineServiceTest(unittest.TestCase):
    def test_service_matches_http_shape(self):
        service = Service()
        payload = {
            "events": [make_grant(), make_amend()],
            "queries": [make_query(as_of="2026-04-01T00:00:00Z")],
        }
        snapshot = copy.deepcopy(payload)
        results = service.consent_timeline(payload)
        self.assertEqual(payload, snapshot)
        self.assertEqual(results[0]["status"], "active")
        self.assertEqual(results[0]["version"], 2)
        self.assertEqual(service.consent_timeline(payload), results)


if __name__ == "__main__":
    unittest.main()
