import copy
import hashlib
import http.client
import json
import threading
import unittest
from http.server import ThreadingHTTPServer

from privacare.audit import ZERO_HASH, _serialize
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


def make_event(event_id="evt-1", **overrides):
    event = {
        "event_id": event_id,
        "occurred_at": "2026-06-01T12:00:00Z",
        "actor_id": "dr-1",
        "action": "read",
        "resource": "record-1",
        "purpose": "treatment",
        "outcome": "allowed",
    }
    event.update(overrides)
    return event


def canonical(event):
    """Independent canonicalization: keys sorted, compact separators."""
    return json.dumps(event, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


class CanonicalizationTest(unittest.TestCase):
    def test_numbers(self):
        cases = {
            0: "0",
            -0.0: "0",
            1: "1",
            1.0: "1",
            1.5: "1.5",
            -2.25: "-2.25",
            0.1: "0.1",
            1e20: "100000000000000000000",
            1e21: "1e+21",
            1e-6: "0.000001",
            1e-7: "1e-7",
            1.5e-7: "1.5e-7",
            123456789.123: "123456789.123",
        }
        for value, expected in cases.items():
            with self.subTest(value=value):
                self.assertEqual(_serialize(value), expected)

    def test_strings(self):
        self.assertEqual(_serialize('a"b\\c'), '"a\\"b\\\\c"')
        self.assertEqual(_serialize("\u0001\u001f"), '"\\u0001\\u001f"')
        self.assertEqual(_serialize("\b\t\n\f\r"), '"\\b\\t\\n\\f\\r"')
        self.assertEqual(_serialize("患者"), '"患者"')

    def test_key_order(self):
        self.assertEqual(_serialize({"b": 1, "a": 2}), '{"a":2,"b":1}')
        self.assertEqual(_serialize({"é": 1, "e": 2}), '{"e":2,"é":1}')

    def test_structures(self):
        self.assertEqual(_serialize({"x": [1, None, True, {"y": []}]}), '{"x":[1,null,true,{"y":[]}]}')


class AuditChainHttpTest(HttpTestBase):
    def post_chain(self, payload, content_type="application/json"):
        body = payload if isinstance(payload, (str, bytes)) else json.dumps(payload)
        return self.request("POST", "/v1/audit/chain", body=body, content_type=content_type)

    def post_verify(self, payload, content_type="application/json"):
        body = payload if isinstance(payload, (str, bytes)) else json.dumps(payload)
        return self.request("POST", "/v1/audit/verify", body=body, content_type=content_type)

    def test_chain_happy_path(self):
        events = [make_event("e-1"), make_event("e-2", outcome="denied", details={"reason": "no consent"})]
        status, payload = self.post_chain({"events": events})
        self.assertEqual(status, 200)
        self.assertEqual(payload["anchor_hash"], ZERO_HASH)
        evidence = payload["evidence"]
        self.assertEqual(len(evidence), 2)
        previous = ZERO_HASH
        for index, (event, entry) in enumerate(zip(events, evidence)):
            expected = hashlib.sha256(bytes.fromhex(previous) + canonical(event)).hexdigest()
            self.assertEqual(
                entry,
                {
                    "index": index,
                    "event_id": event["event_id"],
                    "previous_hash": previous,
                    "evidence_hash": expected,
                },
            )
            previous = expected
        self.assertEqual(payload["final_hash"], previous)

    def test_chain_is_deterministic_and_does_not_mutate(self):
        body = {"events": [make_event("e-1", details={"b": 1, "a": [2, 3]})]}
        snapshot = copy.deepcopy(body)
        first = self.post_chain(body)
        second = self.post_chain(body)
        self.assertEqual(first, second)
        self.assertEqual(body, snapshot)

    def test_chain_anchor_linkage(self):
        first_status, first = self.post_chain({"events": [make_event("e-1")]})
        self.assertEqual(first_status, 200)
        second_status, second = self.post_chain(
            {"events": [make_event("e-2")], "anchor_hash": first["final_hash"].upper()}
        )
        self.assertEqual(second_status, 200)
        self.assertEqual(second["anchor_hash"], first["final_hash"])
        self.assertEqual(second["evidence"][0]["previous_hash"], first["final_hash"])

    def test_verify_valid_chain(self):
        events = [make_event("e-1"), make_event("e-2")]
        _, chain = self.post_chain({"events": events})
        status, payload = self.post_verify(
            {"events": events, "anchor_hash": chain["anchor_hash"], "evidence": chain["evidence"]}
        )
        self.assertEqual(status, 200)
        self.assertEqual(payload, {"valid": True, "first_invalid_index": None})

    def test_verify_detects_tampering(self):
        events = [make_event("e-1"), make_event("e-2"), make_event("e-3")]
        _, chain = self.post_chain({"events": events})
        tampered = copy.deepcopy(events)
        tampered[1]["outcome"] = "denied"
        status, payload = self.post_verify({"events": tampered, "evidence": chain["evidence"]})
        self.assertEqual(status, 200)
        self.assertEqual(payload, {"valid": False, "first_invalid_index": 1})

    def test_verify_detects_wrong_anchor(self):
        events = [make_event("e-1")]
        _, chain = self.post_chain({"events": events})
        status, payload = self.post_verify(
            {"events": events, "anchor_hash": "f" * 64, "evidence": chain["evidence"]}
        )
        self.assertEqual(status, 200)
        self.assertEqual(payload, {"valid": False, "first_invalid_index": 0})

    def test_invalid_request(self):
        for body in ("[]", "{}", '{"events": []}', '{"events": "x"}'):
            with self.subTest(body=body):
                for post in (self.post_chain, self.post_verify):
                    status, payload = post(body)
                    self.assertEqual(status, 422)
                    self.assertEqual(payload["error"]["code"], "invalid_request")

    def test_invalid_audit_event(self):
        bad_events = [
            make_event(event_id=""),
            make_event("e-1", occurred_at="2026-06-01 12:00:00"),
            make_event("e-1", occurred_at="2026-06-01T12:00:00"),
            make_event("e-1", outcome="maybe"),
            make_event("e-1", details="nope"),
            {k: v for k, v in make_event().items() if k != "purpose"},
        ]
        for event in bad_events:
            with self.subTest(event=event):
                status, payload = self.post_chain({"events": [event]})
                self.assertEqual(status, 422)
                self.assertEqual(payload["error"]["code"], "invalid_audit_event")
        status, payload = self.post_chain({"events": [make_event("dup"), make_event("dup")]})
        self.assertEqual(status, 422)
        self.assertEqual(payload["error"]["code"], "invalid_audit_event")

    def test_invalid_anchor(self):
        for anchor in ("xyz", "0" * 63, "0" * 65, 42, None):
            with self.subTest(anchor=anchor):
                status, payload = self.post_chain({"events": [make_event()], "anchor_hash": anchor})
                self.assertEqual(status, 422)
                self.assertEqual(payload["error"]["code"], "invalid_anchor")

    def test_invalid_evidence_chain(self):
        events = [make_event("e-1")]
        _, chain = self.post_chain({"events": events})
        good = chain["evidence"][0]
        cases = [
            "not-a-list",
            [],
            [{"index": 0, "event_id": "e-1", "previous_hash": ZERO_HASH}],
            [{**good, "evidence_hash": "zz" + good["evidence_hash"][2:]}],
            [{**good, "previous_hash": "0" * 10}],
        ]
        for evidence in cases:
            with self.subTest(evidence=evidence):
                status, payload = self.post_verify({"events": events, "evidence": evidence})
                self.assertEqual(status, 422)
                self.assertEqual(payload["error"]["code"], "invalid_evidence_chain")

    def test_error_responses_do_not_echo_event_values(self):
        secret = "actor-11010519491231002X"
        status, payload = self.post_chain({"events": [make_event(actor_id=secret, outcome="bad")]})
        self.assertEqual(status, 422)
        self.assertNotIn(secret, json.dumps(payload))

    def test_http_semantics(self):
        status, payload = self.request("GET", "/v1/audit/chain")
        self.assertEqual(status, 405)
        self.assertEqual(payload["error"]["code"], "method_not_allowed")
        status, payload = self.request("GET", "/v1/audit/verify")
        self.assertEqual(status, 405)
        status, payload = self.request("GET", "/v1/audit/nope")
        self.assertEqual(status, 404)
        self.assertEqual(payload["error"]["code"], "not_found")
        status, payload = self.post_chain({"events": [make_event()]}, content_type="text/plain")
        self.assertEqual(status, 415)
        self.assertEqual(payload["error"]["code"], "unsupported_media_type")
        status, payload = self.post_chain("{not json")
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"]["code"], "invalid_json")

    def test_healthz_unchanged(self):
        status, payload = self.request("GET", "/healthz")
        self.assertEqual(status, 200)
        self.assertEqual(payload["status"], "ok")


if __name__ == "__main__":
    unittest.main()
