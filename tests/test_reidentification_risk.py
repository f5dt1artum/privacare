import copy
import http.client
import json
import threading
import unittest
from http.server import ThreadingHTTPServer

from privacare.server import Handler
from privacare.service import Service

PATH = "/v1/reidentification-risk"


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


def make_payload(**overrides):
    payload = {
        "records": [
            {"age": 30, "city": "北京"},
            {"age": 30, "city": "北京"},
            {"age": 40, "city": "上海"},
        ],
        "quasi_identifiers": ["/age", "/city"],
        "k": 2,
    }
    payload.update(overrides)
    return payload


class ReidentificationRiskHttpTest(HttpTestBase):
    def post(self, payload, content_type="application/json"):
        body = payload if isinstance(payload, (str, bytes)) else json.dumps(payload)
        return self.request("POST", PATH, body=body, content_type=content_type)

    def test_happy_path(self):
        status, payload = self.post(make_payload())
        self.assertEqual(status, 200)
        self.assertEqual(
            payload["summary"],
            {
                "k": 2,
                "record_count": 3,
                "equivalence_class_count": 2,
                "minimum_class_size": 1,
                "at_risk_records": 1,
                "at_risk_rate": 0.333333,
            },
        )
        self.assertEqual(
            payload["results"],
            [
                {"index": 0, "class_size": 2, "risk_score": 0.5, "at_risk": False},
                {"index": 1, "class_size": 2, "risk_score": 0.5, "at_risk": False},
                {"index": 2, "class_size": 1, "risk_score": 1.0, "at_risk": True},
            ],
        )

    def test_rounding_half_up(self):
        # 1/128 = 0.0078125 -> half-up gives 0.007813 (half-even would give 0.007812)
        records = [{"g": 1}] * 128
        status, payload = self.post(
            {"records": records, "quasi_identifiers": ["/g"], "k": 2}
        )
        self.assertEqual(status, 200)
        self.assertEqual(payload["results"][0]["risk_score"], 0.007813)
        self.assertEqual(payload["summary"]["minimum_class_size"], 128)
        self.assertEqual(payload["summary"]["at_risk_rate"], 0.0)

    def test_risk_score_rounding(self):
        records = [{"g": 1}] * 3 + [{"g": 2}] * 4
        status, payload = self.post(
            {"records": records, "quasi_identifiers": ["/g"], "k": 2}
        )
        self.assertEqual(status, 200)
        # 1/3 -> 0.333333, 1/4 -> 0.25
        self.assertEqual(payload["results"][0]["risk_score"], 0.333333)
        self.assertEqual(payload["results"][3]["risk_score"], 0.25)

    def test_grouping_semantics(self):
        records = [
            {"v": 1},        # number 1
            {"v": 1.0},      # number 1.0 == 1
            {"v": True},     # bool, distinct from number
            {"v": "A"},      # case-sensitive string
            {"v": "a"},
            {"v": None},     # null participates in grouping
            {"v": None},
        ]
        status, payload = self.post(
            {"records": records, "quasi_identifiers": ["/v"], "k": 2}
        )
        self.assertEqual(status, 200)
        sizes = [r["class_size"] for r in payload["results"]]
        self.assertEqual(sizes, [2, 2, 1, 1, 1, 2, 2])
        self.assertEqual(payload["summary"]["equivalence_class_count"], 5)

    def test_nested_and_array_pointers(self):
        records = [
            {"demo": {"age": 30}, "tags": ["x", "y"]},
            {"demo": {"age": 30}, "tags": ["x", "y"]},
            {"demo": {"age": 31}, "tags": ["x", "z"]},
        ]
        status, payload = self.post(
            {
                "records": records,
                "quasi_identifiers": ["/demo/age", "/tags/1"],
                "k": 2,
            }
        )
        self.assertEqual(status, 200)
        self.assertEqual([r["class_size"] for r in payload["results"]], [2, 2, 1])

    def test_escaped_pointer(self):
        records = [{"a/b": 1, "c~d": 2}, {"a/b": 1, "c~d": 2}]
        status, payload = self.post(
            {
                "records": records,
                "quasi_identifiers": ["/a~1b", "/c~0d"],
                "k": 2,
            }
        )
        self.assertEqual(status, 200)
        self.assertEqual(payload["summary"]["equivalence_class_count"], 1)

    def test_order_independence(self):
        records = [
            {"age": 30, "city": "北京"},
            {"age": 40, "city": "上海"},
            {"age": 30, "city": "北京"},
        ]
        _, forward = self.post(make_payload(records=records))
        _, reversed_payload = self.post(make_payload(records=list(reversed(records))))
        forward_sizes = sorted(r["class_size"] for r in forward["results"])
        reversed_sizes = sorted(r["class_size"] for r in reversed_payload["results"])
        self.assertEqual(forward_sizes, reversed_sizes)
        self.assertEqual(forward["summary"], reversed_payload["summary"])

    def test_no_value_echo(self):
        status, payload = self.post(make_payload())
        self.assertEqual(status, 200)
        body = json.dumps(payload, ensure_ascii=False)
        self.assertNotIn("北京", body)
        self.assertNotIn("上海", body)
        self.assertNotIn("30", body)
        self.assertNotIn("40", body)

    def test_unsupported_media_type(self):
        status, payload = self.post(make_payload(), content_type="text/plain")
        self.assertEqual(status, 415)
        self.assertEqual(payload["error"]["code"], "unsupported_media_type")

    def test_invalid_json(self):
        status, payload = self.post("{not json")
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"]["code"], "invalid_json")

    def test_invalid_request(self):
        for body in ("[]", "{}", '{"records": []}', '{"records": [1]}'):
            with self.subTest(body=body):
                status, payload = self.post(body)
                self.assertEqual(status, 422)
                self.assertEqual(payload["error"]["code"], "invalid_request")

    def test_invalid_quasi_identifiers_structure(self):
        base = make_payload()
        for bad in (None, "/age", [], ["/age", "/age"], ["/age", 1], ["/age", "age"], ["/age", "/a~2b"]):
            with self.subTest(bad=bad):
                payload = dict(base)
                if bad is None:
                    payload.pop("quasi_identifiers")
                else:
                    payload["quasi_identifiers"] = bad
                status, payload = self.post(payload)
                self.assertEqual(status, 422)
                self.assertEqual(payload["error"]["code"], "invalid_quasi_identifiers")

    def test_invalid_quasi_identifiers_resolution(self):
        base = make_payload()
        for bad in (["/missing"], ["/age/0"], ["/age", ""], ["/city", "/age/deep"]):
            with self.subTest(bad=bad):
                payload = dict(base, quasi_identifiers=bad)
                status, payload = self.post(payload)
                self.assertEqual(status, 422)
                self.assertEqual(payload["error"]["code"], "invalid_quasi_identifiers")

    def test_pointer_to_container_fails(self):
        payload = make_payload(
            records=[{"demo": {"age": 30}}],
            quasi_identifiers=["/demo"],
        )
        status, payload = self.post(payload)
        self.assertEqual(status, 422)
        self.assertEqual(payload["error"]["code"], "invalid_quasi_identifiers")

    def test_array_index_out_of_range_fails(self):
        payload = make_payload(
            records=[{"tags": ["x"]}],
            quasi_identifiers=["/tags/1"],
        )
        status, payload = self.post(payload)
        self.assertEqual(status, 422)
        self.assertEqual(payload["error"]["code"], "invalid_quasi_identifiers")

    def test_invalid_k(self):
        base = make_payload()
        for bad in (True, 2.0, 1.5, "2", 1, 0, -3, None):
            with self.subTest(bad=bad):
                payload = dict(base)
                if bad is None:
                    payload.pop("k")
                else:
                    payload["k"] = bad
                status, payload = self.post(payload)
                self.assertEqual(status, 422)
                self.assertEqual(payload["error"]["code"], "invalid_k")

    def test_method_not_allowed(self):
        for method in ("GET", "PUT", "DELETE", "PATCH"):
            with self.subTest(method=method):
                status, payload = self.request(method, PATH)
                self.assertEqual(status, 405)
                self.assertEqual(payload["error"]["code"], "method_not_allowed")

    def test_unknown_path_404(self):
        status, payload = self.request("POST", "/v1/reidentification")
        self.assertEqual(status, 404)
        self.assertEqual(payload["error"]["code"], "not_found")


class ReidentificationRiskServiceTest(unittest.TestCase):
    def test_in_process_call_is_pure_and_deterministic(self):
        service = Service()
        payload = make_payload()
        snapshot = copy.deepcopy(payload)
        first = service.reidentification_risk(payload)
        second = service.reidentification_risk(payload)
        self.assertEqual(payload, snapshot)
        self.assertEqual(first, second)
        self.assertEqual(first["summary"]["record_count"], 3)


if __name__ == "__main__":
    unittest.main()
