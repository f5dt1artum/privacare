import hashlib
import http.client
import json
import threading
import unittest
from http.server import ThreadingHTTPServer

from privacare.audit import (
    ZERO_ANCHOR,
    InvalidAnchor,
    InvalidAuditEvent,
    InvalidEvidenceChain,
    _canonicalize,
    audit_chain_request,
    audit_verify_request,
)
from privacare.classifier import InvalidRequest
from privacare.server import Handler


def make_event(event_id="evt-1", **overrides):
    event = {
        "event_id": event_id,
        "occurred_at": "2026-09-01T08:30:00+08:00",
        "actor_id": "dr-li",
        "action": "read",
        "resource": "record/123",
        "purpose": "treatment",
        "outcome": "allowed",
    }
    event.update(overrides)
    return event


class CanonicalizeTest(unittest.TestCase):
    def test_scalars_and_key_sorting(self):
        self.assertEqual(_canonicalize({"b": 1, "a": 2}), '{"a":2,"b":1}')
        self.assertEqual(_canonicalize([1, "two", True, None, False]), '[1,"two",true,null,false]')
        self.assertEqual(_canonicalize({}), "{}")
        self.assertEqual(_canonicalize([]), "[]")
        self.assertEqual(_canonicalize({"10": 1, "2": 2, "1": 3}), '{"1":3,"10":1,"2":2}')

    def test_string_escapes(self):
        self.assertEqual(_canonicalize('a"b\\c\n'), '"a\\"b\\\\c\\n"')
        self.assertEqual(_canonicalize("\x01\x1f"), '"\\u0001\\u001f"')
        self.assertEqual(_canonicalize("é你"), '"é你"')

    def test_numbers(self):
        cases = [
            (0, "0"),
            (5, "5"),
            (-7, "-7"),
            (1.0, "1"),
            (100.0, "100"),
            (3.14, "3.14"),
            (-0.0, "0"),
            (0.5, "0.5"),
            (0.000001, "0.000001"),
            (1e-7, "1e-7"),
            (1.5e-7, "1.5e-7"),
            (1e20, "1" + "0" * 20),
            (1e21, "1e+21"),
            (10**20, "1" + "0" * 20),
            (10**21, "1e+21"),
            (1.2345678901234568e20, "123456789012345680000"),
        ]
        for value, expected in cases:
            with self.subTest(value=value):
                self.assertEqual(_canonicalize(value), expected)

    def test_keys_sort_by_utf16_code_units(self):
        # U+1F600 (surrogate pair, lead unit 0xD83D) sorts before U+FD50
        # under UTF-16 code units, but after it under code points.
        value = {"\U0001f600": 1, "\ufd50": 2}
        self.assertEqual(_canonicalize(value), '{"\U0001f600":1,"\ufd50":2}')

    def test_non_finite_number_rejected(self):
        with self.assertRaises(InvalidAuditEvent):
            _canonicalize(float("nan"))
        with self.assertRaises(InvalidAuditEvent):
            _canonicalize(float("inf"))


class ChainTest(unittest.TestCase):
    def test_known_vector(self):
        event = {
            "event_id": "e1",
            "occurred_at": "2026-01-01T00:00:00Z",
            "actor_id": "a",
            "action": "read",
            "resource": "r",
            "purpose": "p",
            "outcome": "allowed",
        }
        result = audit_chain_request({"events": [event]})
        canonical = (
            b'{"action":"read","actor_id":"a","event_id":"e1",'
            b'"occurred_at":"2026-01-01T00:00:00Z","outcome":"allowed",'
            b'"purpose":"p","resource":"r"}'
        )
        expected = hashlib.sha256(bytes(32) + canonical).hexdigest()
        self.assertEqual(result["anchor_hash"], ZERO_ANCHOR)
        self.assertEqual(result["final_hash"], expected)
        self.assertEqual(
            result["evidence"],
            [
                {
                    "index": 0,
                    "event_id": "e1",
                    "previous_hash": ZERO_ANCHOR,
                    "evidence_hash": expected,
                }
            ],
        )

    def test_chain_links(self):
        events = [make_event("e1"), make_event("e2", outcome="denied")]
        result = audit_chain_request({"events": events})
        self.assertEqual([e["index"] for e in result["evidence"]], [0, 1])
        self.assertEqual(
            result["evidence"][1]["previous_hash"],
            result["evidence"][0]["evidence_hash"],
        )
        self.assertEqual(result["final_hash"], result["evidence"][-1]["evidence_hash"])

    def test_anchor_chaining_across_batches(self):
        first = audit_chain_request({"events": [make_event("e1")]})
        second = audit_chain_request(
            {"events": [make_event("e2")], "anchor_hash": first["final_hash"]}
        )
        self.assertEqual(second["anchor_hash"], first["final_hash"])
        self.assertEqual(second["evidence"][0]["previous_hash"], first["final_hash"])
        verify = audit_verify_request(
            {
                "events": [make_event("e2")],
                "anchor_hash": first["final_hash"],
                "evidence": second["evidence"],
            }
        )
        self.assertEqual(verify, {"valid": True, "first_invalid_index": None})

    def test_uppercase_anchor_normalized(self):
        result = audit_chain_request({"events": [make_event()], "anchor_hash": "A" * 64})
        self.assertEqual(result["anchor_hash"], "a" * 64)
        self.assertEqual(result["evidence"][0]["previous_hash"], "a" * 64)

    def test_extension_fields_and_details_join_evidence(self):
        base = audit_chain_request({"events": [make_event("e1")]})
        extended = audit_chain_request(
            {"events": [make_event("e1", details={"ip": "10.0.0.1"}, extra="x")]}
        )
        self.assertNotEqual(base["final_hash"], extended["final_hash"])

    def test_deterministic_and_no_mutation(self):
        payload = {"events": [make_event("e1", details={"b": 1, "a": {"y": [1, 2]}})]}
        snapshot = json.loads(json.dumps(payload))
        first = audit_chain_request(payload)
        second = audit_chain_request(payload)
        self.assertEqual(first, second)
        self.assertEqual(payload, snapshot)


class ChainValidationTest(unittest.TestCase):
    def test_invalid_request(self):
        for payload in (None, [], "x", {}, {"events": []}, {"events": "x"}):
            with self.subTest(payload=payload):
                with self.assertRaises(InvalidRequest):
                    audit_chain_request(payload)

    def test_invalid_events(self):
        bad_events = [
            1,
            "evt",
            {},
            make_event(event_id=""),
            make_event(event_id=1),
            make_event(actor_id=""),
            make_event(action=3),
            make_event(resource=None),
            make_event(purpose=""),
            make_event(occurred_at="2026-01-01"),
            make_event(occurred_at="2026-01-01T00:00:00"),
            make_event(occurred_at="2026-13-01T00:00:00Z"),
            make_event(occurred_at=0),
            make_event(outcome="maybe"),
            make_event(outcome=1),
            make_event(details=[1, 2]),
            make_event(details="x"),
        ]
        for event in bad_events:
            with self.subTest(event=event):
                with self.assertRaises(InvalidAuditEvent):
                    audit_chain_request({"events": [event]})

    def test_missing_each_required_field(self):
        for field in (
            "event_id",
            "occurred_at",
            "actor_id",
            "action",
            "resource",
            "purpose",
            "outcome",
        ):
            with self.subTest(field=field):
                event = make_event()
                del event[field]
                with self.assertRaises(InvalidAuditEvent):
                    audit_chain_request({"events": [event]})

    def test_duplicate_event_id(self):
        with self.assertRaises(InvalidAuditEvent):
            audit_chain_request({"events": [make_event("e1"), make_event("e1")]})

    def test_invalid_anchor(self):
        for anchor in ("xyz", "a" * 63, "a" * 65, 123, ["0" * 64], {"h": 1}):
            with self.subTest(anchor=anchor):
                with self.assertRaises(InvalidAnchor):
                    audit_chain_request({"events": [make_event()], "anchor_hash": anchor})


class VerifyTest(unittest.TestCase):
    def setUp(self):
        self.events = [
            make_event("e1"),
            make_event("e2", outcome="denied", details={"reason": "no consent"}),
        ]
        self.chain = audit_chain_request({"events": self.events})

    def verify_payload(self, **overrides):
        payload = {"events": self.events, "evidence": self.chain["evidence"]}
        payload.update(overrides)
        return payload

    def test_valid(self):
        result = audit_verify_request(self.verify_payload())
        self.assertEqual(result, {"valid": True, "first_invalid_index": None})

    def test_tampered_event(self):
        events = json.loads(json.dumps(self.events))
        events[1]["actor_id"] = "mallory"
        result = audit_verify_request(self.verify_payload(events=events))
        self.assertEqual(result, {"valid": False, "first_invalid_index": 1})

    def test_tampered_evidence_hash(self):
        evidence = json.loads(json.dumps(self.chain["evidence"]))
        evidence[0]["evidence_hash"] = "0" * 64
        result = audit_verify_request(self.verify_payload(evidence=evidence))
        self.assertEqual(result, {"valid": False, "first_invalid_index": 0})

    def test_tampered_previous_hash(self):
        evidence = json.loads(json.dumps(self.chain["evidence"]))
        evidence[1]["previous_hash"] = "f" * 64
        result = audit_verify_request(self.verify_payload(evidence=evidence))
        self.assertEqual(result, {"valid": False, "first_invalid_index": 1})

    def test_tampered_index_and_event_id(self):
        evidence = json.loads(json.dumps(self.chain["evidence"]))
        evidence[1]["index"] = 5
        result = audit_verify_request(self.verify_payload(evidence=evidence))
        self.assertEqual(result, {"valid": False, "first_invalid_index": 1})
        evidence = json.loads(json.dumps(self.chain["evidence"]))
        evidence[0]["event_id"] = "e2"
        result = audit_verify_request(self.verify_payload(evidence=evidence))
        self.assertEqual(result, {"valid": False, "first_invalid_index": 0})

    def test_wrong_anchor(self):
        result = audit_verify_request(self.verify_payload(anchor_hash="1" * 64))
        self.assertEqual(result, {"valid": False, "first_invalid_index": 0})

    def test_invalid_evidence_structure(self):
        bad = [
            None,
            "x",
            [],
            self.chain["evidence"][:1],
            [1, 2],
            [{}, {}],
        ]
        for evidence in bad:
            with self.subTest(evidence=evidence):
                with self.assertRaises(InvalidEvidenceChain):
                    audit_verify_request(self.verify_payload(evidence=evidence))

    def test_invalid_evidence_hash_format(self):
        evidence = json.loads(json.dumps(self.chain["evidence"]))
        evidence[0]["previous_hash"] = "zz"
        with self.assertRaises(InvalidEvidenceChain):
            audit_verify_request(self.verify_payload(evidence=evidence))

    def test_verify_validates_events_and_anchor(self):
        with self.assertRaises(InvalidAuditEvent):
            audit_verify_request(self.verify_payload(events=[make_event("e1"), make_event("e1")]))
        with self.assertRaises(InvalidAnchor):
            audit_verify_request(self.verify_payload(anchor_hash="nope"))
        with self.assertRaises(InvalidRequest):
            audit_verify_request({"evidence": []})


class AuditHttpTest(unittest.TestCase):
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

    def request(self, method, path, body=None, content_type="application/json"):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        headers = {}
        if content_type is not None:
            headers["Content-Type"] = content_type
        conn.request(method, path, body=body, headers=headers)
        resp = conn.getresponse()
        raw = resp.read()
        conn.close()
        return resp.status, json.loads(raw)

    def post(self, path, payload, content_type="application/json"):
        body = payload if isinstance(payload, (str, bytes)) else json.dumps(payload)
        return self.request("POST", path, body=body, content_type=content_type)

    def test_chain_and_verify_roundtrip(self):
        events = [make_event("e1"), make_event("e2", outcome="denied")]
        status, payload = self.post("/v1/audit/chain", {"events": events})
        self.assertEqual(status, 200)
        self.assertEqual(payload["anchor_hash"], ZERO_ANCHOR)
        self.assertEqual(len(payload["evidence"]), 2)
        self.assertEqual(payload["final_hash"], payload["evidence"][-1]["evidence_hash"])

        status, payload = self.post(
            "/v1/audit/verify",
            {
                "events": events,
                "anchor_hash": payload["anchor_hash"],
                "evidence": payload["evidence"],
            },
        )
        self.assertEqual(status, 200)
        self.assertEqual(payload, {"valid": True, "first_invalid_index": None})

    def test_verify_detects_tampering_over_http(self):
        events = [make_event("e1"), make_event("e2")]
        _, chain = self.post("/v1/audit/chain", {"events": events})
        events[1]["resource"] = "record/999"
        status, payload = self.post(
            "/v1/audit/verify", {"events": events, "evidence": chain["evidence"]}
        )
        self.assertEqual(status, 200)
        self.assertEqual(payload, {"valid": False, "first_invalid_index": 1})

    def test_error_codes(self):
        cases = [
            ("/v1/audit/chain", {}, "invalid_request"),
            ("/v1/audit/chain", {"events": []}, "invalid_request"),
            ("/v1/audit/chain", {"events": [{}]}, "invalid_audit_event"),
            (
                "/v1/audit/chain",
                {"events": [make_event()], "anchor_hash": "bad"},
                "invalid_anchor",
            ),
            ("/v1/audit/verify", {}, "invalid_request"),
            (
                "/v1/audit/verify",
                {"events": [make_event()], "evidence": []},
                "invalid_evidence_chain",
            ),
            (
                "/v1/audit/verify",
                {
                    "events": [make_event()],
                    "evidence": [
                        {"index": 0, "event_id": "evt-1", "previous_hash": "0" * 64}
                    ],
                },
                "invalid_evidence_chain",
            ),
        ]
        for path, body, code in cases:
            with self.subTest(path=path, body=body):
                status, payload = self.post(path, body)
                self.assertEqual(status, 422)
                self.assertEqual(payload["error"]["code"], code)

    def test_error_body_has_no_event_values(self):
        secret = "actor-with-secret-identity"
        status, payload = self.post(
            "/v1/audit/chain",
            {"events": [make_event("e1", actor_id=secret), make_event("e1")]},
        )
        self.assertEqual(status, 422)
        self.assertNotIn(secret, json.dumps(payload))

    def test_http_layer_semantics(self):
        for path in ("/v1/audit/chain", "/v1/audit/verify"):
            with self.subTest(path=path):
                status, payload = self.post(path, "{not json")
                self.assertEqual(status, 400)
                self.assertEqual(payload["error"]["code"], "invalid_json")

                status, payload = self.post(path, "{}", content_type="text/plain")
                self.assertEqual(status, 415)
                self.assertEqual(payload["error"]["code"], "unsupported_media_type")

                for method in ("GET", "PUT", "DELETE", "PATCH"):
                    status, payload = self.request(method, path)
                    self.assertEqual(status, 405)
                    self.assertEqual(payload["error"]["code"], "method_not_allowed")

        status, payload = self.request("POST", "/v1/audit")
        self.assertEqual(status, 404)
        self.assertEqual(payload["error"]["code"], "not_found")

    def test_healthz_unchanged(self):
        status, payload = self.request("GET", "/healthz")
        self.assertEqual(status, 200)
        self.assertEqual(payload["status"], "ok")


if __name__ == "__main__":
    unittest.main()
