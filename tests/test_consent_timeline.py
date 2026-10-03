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
        "valid_from": "2026-02-01T00:00:00Z",
        "valid_until": "2026-12-01T00:00:00Z",
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
        "purposes": ["treatment", "research"],
        "data_categories": ["clinical", "contact"],
        "recipients": ["hospital-a", "hospital-b"],
        "valid_from": "2026-04-01T00:00:00Z",
        "valid_until": "2026-10-01T00:00:00Z",
    }
    event.update(overrides)
    return event


def make_revoke(**overrides):
    event = {
        "event_id": "e-3",
        "consent_id": "c-1",
        "version": 3,
        "occurred_at": "2026-05-01T00:00:00Z",
        "type": "revoke",
    }
    event.update(overrides)
    return event


def make_query(**overrides):
    query = {"consent_id": "c-1", "as_of": "2026-06-01T00:00:00Z"}
    query.update(overrides)
    return query


class ConsentTimelineHttpTest(HttpTestBase):
    def post(self, payload, content_type="application/json"):
        body = payload if isinstance(payload, (str, bytes)) else json.dumps(payload)
        return self.request("POST", "/v1/consent/timeline", body=body, content_type=content_type)

    def test_grant_only_statuses(self):
        status, payload = self.post(
            {
                "events": [make_grant()],
                "queries": [
                    make_query(as_of="2025-12-31T23:59:59Z"),  # before grant
                    make_query(as_of="2026-01-15T00:00:00Z"),  # granted, not yet valid
                    make_query(as_of="2026-06-01T00:00:00Z"),  # active
                    make_query(as_of="2026-12-01T00:00:00Z"),  # expired (inclusive end)
                ],
            }
        )
        self.assertEqual(status, 200)
        results = payload["results"]
        self.assertEqual([r["status"] for r in results], ["not_found", "pending", "active", "expired"])
        self.assertEqual(results[0], {"consent_id": "c-1", "status": "not_found"})
        for result in results[1:]:
            self.assertEqual(result["version"], 1)
            self.assertEqual(result["last_event_id"], "e-1")
            self.assertEqual(
                result["snapshot"],
                {
                    "consent_id": "c-1",
                    "subject_id": "subj-1",
                    "purposes": ["treatment"],
                    "data_categories": ["clinical"],
                    "recipients": ["hospital-a"],
                    "valid_from": "2026-02-01T00:00:00Z",
                    "valid_until": "2026-12-01T00:00:00Z",
                },
            )

    def test_valid_from_boundary_is_active(self):
        status, payload = self.post(
            {"events": [make_grant()], "queries": [make_query(as_of="2026-02-01T00:00:00Z")]}
        )
        self.assertEqual(status, 200)
        self.assertEqual(payload["results"][0]["status"], "active")

    def test_amend_replaces_scope_and_validity(self):
        status, payload = self.post(
            {
                "events": [make_grant(), make_amend()],
                "queries": [
                    make_query(as_of="2026-02-15T00:00:00Z"),  # before amend occurred
                    make_query(as_of="2026-03-15T00:00:00Z"),  # amend pending window
                    make_query(as_of="2026-06-01T00:00:00Z"),  # amend active
                    make_query(as_of="2026-11-01T00:00:00Z"),  # amend expired
                ],
            }
        )
        self.assertEqual(status, 200)
        results = payload["results"]
        self.assertEqual([r["status"] for r in results], ["active", "pending", "active", "expired"])
        self.assertEqual([r["version"] for r in results], [1, 2, 2, 2])
        self.assertEqual(results[1]["last_event_id"], "e-2")
        self.assertEqual(
            results[2]["snapshot"],
            {
                "consent_id": "c-1",
                "subject_id": "subj-1",
                "purposes": ["research", "treatment"],
                "data_categories": ["clinical", "contact"],
                "recipients": ["hospital-a", "hospital-b"],
                "valid_from": "2026-04-01T00:00:00Z",
                "valid_until": "2026-10-01T00:00:00Z",
            },
        )

    def test_revoke_wins_and_keeps_last_snapshot(self):
        status, payload = self.post(
            {
                "events": [make_grant(), make_amend(), make_revoke()],
                "queries": [make_query(as_of="2026-06-01T00:00:00Z")],
            }
        )
        self.assertEqual(status, 200)
        result = payload["results"][0]
        self.assertEqual(result["status"], "revoked")
        self.assertEqual(result["version"], 3)
        self.assertEqual(result["last_event_id"], "e-3")
        self.assertEqual(result["snapshot"]["valid_from"], "2026-04-01T00:00:00Z")
        self.assertEqual(result["snapshot"]["subject_id"], "subj-1")

    def test_unknown_consent_is_not_found(self):
        status, payload = self.post(
            {"events": [make_grant()], "queries": [make_query(consent_id="c-other")]}
        )
        self.assertEqual(status, 200)
        self.assertEqual(payload["results"], [{"consent_id": "c-other", "status": "not_found"}])

    def test_event_order_does_not_matter(self):
        events = [make_grant(), make_amend(), make_revoke()]
        queries = [make_query(as_of="2026-06-01T00:00:00Z"), make_query(as_of="2026-02-15T00:00:00Z")]
        status, forward = self.post({"events": events, "queries": queries})
        self.assertEqual(status, 200)
        status, reverse = self.post({"events": list(reversed(events)), "queries": queries})
        self.assertEqual(status, 200)
        self.assertEqual(forward, reverse)

    def test_results_follow_query_order(self):
        status, payload = self.post(
            {
                "events": [make_grant()],
                "queries": [
                    make_query(consent_id="c-missing"),
                    make_query(as_of="2026-06-01T00:00:00Z"),
                ],
            }
        )
        self.assertEqual(status, 200)
        results = payload["results"]
        self.assertEqual([r["consent_id"] for r in results], ["c-missing", "c-1"])
        self.assertEqual([r["status"] for r in results], ["not_found", "active"])

    def test_timezone_offsets_compare_by_instant(self):
        status, payload = self.post(
            {
                "events": [make_grant(occurred_at="2026-01-01T08:00:00+08:00")],
                "queries": [
                    make_query(as_of="2025-12-31T23:59:59Z"),
                    make_query(as_of="2026-01-01T00:00:00Z"),
                ],
            }
        )
        self.assertEqual(status, 200)
        self.assertEqual([r["status"] for r in payload["results"]], ["not_found", "pending"])

    def test_snapshot_timestamps_normalized_to_utc(self):
        status, payload = self.post(
            {
                "events": [make_grant(valid_from="2026-02-01T08:00:00+08:00")],
                "queries": [make_query(as_of="2026-06-01T00:00:00Z")],
            }
        )
        self.assertEqual(status, 200)
        self.assertEqual(payload["results"][0]["snapshot"]["valid_from"], "2026-02-01T00:00:00Z")

    def test_no_mutation_and_deterministic(self):
        payload = {
            "events": [make_grant(), make_amend(), make_revoke()],
            "queries": [make_query(), make_query(consent_id="c-missing")],
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
            make_grant(version="1"),
            make_grant(version=True),
            make_grant(occurred_at="2026-01-01"),
            make_grant(occurred_at="2026-01-01T00:00:00"),
            make_grant(occurred_at="not-a-time"),
            make_grant(type="renew"),
            make_grant(type=""),
        ]
        for event in cases:
            with self.subTest(event=event):
                status, payload = self.post({"events": [event], "queries": [make_query()]})
                self.assertEqual(status, 422)
                self.assertEqual(payload["error"]["code"], "invalid_consent_event")

    def test_invalid_grant_scope(self):
        cases = [
            make_grant(subject_id=""),
            make_grant(purposes=[]),
            make_grant(purposes=["a", "a"]),
            make_grant(data_categories=[]),
            make_grant(data_categories=["unknown"]),
            make_grant(recipients=[]),
            make_grant(recipients=["a", "a"]),
            make_grant(valid_from="2026-01-01"),
            make_grant(valid_until="2026-02-01T00:00:00Z"),  # equal to valid_from
            make_grant(valid_from="2026-12-01T00:00:00Z", valid_until="2026-02-01T00:00:00Z"),
        ]
        for event in cases:
            with self.subTest(event=event):
                status, payload = self.post({"events": [event], "queries": [make_query()]})
                self.assertEqual(status, 422)
                self.assertEqual(payload["error"]["code"], "invalid_consent_event")

    def test_invalid_event_sequence(self):
        cases = [
            # duplicate event_id
            [make_grant(), make_grant(consent_id="c-2")],
            # grant not at version 1
            [make_grant(version=2), make_amend(version=1)],
            # versions not consecutive
            [make_grant(), make_amend(version=3)],
            # duplicate version
            [make_grant(), make_amend(version=1, event_id="e-2")],
            # first event not a grant
            [make_amend(version=1, event_id="e-1"), make_grant(version=2, event_id="e-2")],
            # second grant
            [make_grant(), make_grant(event_id="e-2", version=2)],
            # events after revoke
            [make_grant(), make_revoke(version=2, event_id="e-2"), make_amend(version=3, event_id="e-3")],
            # double revoke
            [make_grant(), make_revoke(version=2, event_id="e-2"), make_revoke(version=3, event_id="e-3")],
            # occurred_at goes backwards
            [make_grant(), make_amend(occurred_at="2025-12-01T00:00:00Z")],
            # amend carrying subject_id
            [make_grant(), make_amend(subject_id="subj-1")],
            # revoke carrying state fields
            [make_grant(), make_revoke(version=2, event_id="e-2", subject_id="subj-1")],
            [make_grant(), make_revoke(version=2, event_id="e-2", purposes=["treatment"])],
            [make_grant(), make_revoke(version=2, event_id="e-2", valid_until="2027-01-01T00:00:00Z")],
        ]
        for events in cases:
            with self.subTest(events=events):
                status, payload = self.post({"events": events, "queries": [make_query()]})
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
            make_query(as_of="2026-06-01T00:00:00"),
            make_query(as_of="not-a-time"),
        ]
        for query in cases:
            with self.subTest(query=query):
                status, payload = self.post({"events": [make_grant()], "queries": [query]})
                self.assertEqual(status, 422)
                self.assertEqual(payload["error"]["code"], "invalid_query")

    def test_no_partial_results_on_any_failure(self):
        status, payload = self.post(
            {
                "events": [make_grant()],
                "queries": [make_query(), make_query(as_of="not-a-time")],
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


if __name__ == "__main__":
    unittest.main()
