import copy
import http.client
import json
import threading
import unittest
from http.server import ThreadingHTTPServer

from privacare.classifier import InvalidRequest, InvalidSchema
from privacare.deidentifier import InvalidPolicy
from privacare.server import Handler
from privacare.service import Service

VALID_ID = "11010519491231002X"  # checksum-valid mainland ID
VALID_CARD = "4111111111111111"  # Luhn-valid card number


def deidentify(payload):
    return Service().deidentify(payload)


class PolicyActionTest(unittest.TestCase):
    def test_keep_redact_drop(self):
        [result] = deidentify(
            {
                "records": [{"name": "张三", "email": "a@b.com", "age": 45, "note": "plain"}],
                "policy": {
                    "direct_identifier": "drop",
                    "contact": "redact",
                    "quasi_identifier": "keep",
                },
            }
        )
        record = result["record"]
        self.assertNotIn("name", record)
        self.assertIsNone(record["email"])
        self.assertEqual(record["age"], 45)
        self.assertEqual(record["note"], "plain")
        transformations = {t["path"]: t for t in result["transformations"]}
        self.assertEqual(
            transformations["/name"],
            {"path": "/name", "action": "drop", "categories": ["direct_identifier"]},
        )
        self.assertEqual(
            transformations["/email"],
            {"path": "/email", "action": "redact", "categories": ["contact"]},
        )
        self.assertNotIn("/age", transformations)
        self.assertNotIn("/note", transformations)

    def test_unconfigured_categories_default_to_keep(self):
        [result] = deidentify(
            {
                "records": [{"name": "张三", "age": 45}],
                "policy": {"direct_identifier": "redact"},
            }
        )
        self.assertIsNone(result["record"]["name"])
        self.assertEqual(result["record"]["age"], 45)
        self.assertEqual([t["path"] for t in result["transformations"]], ["/name"])

    def test_multi_category_priority_drop_over_redact_over_keep(self):
        record = {"id_card": VALID_ID}  # direct_identifier via name and value
        payload = {
            "records": [record],
            "schema": {"/id_card": ["contact", "clinical"]},
        }
        # contact=redact + clinical=keep + direct=keep -> redact wins over keep
        [result] = deidentify(
            {**payload, "policy": {"contact": "redact", "clinical": "keep"}}
        )
        self.assertIsNone(result["record"]["id_card"])
        [t] = result["transformations"]
        self.assertEqual(t["action"], "redact")
        self.assertEqual(
            t["categories"], ["direct_identifier", "contact", "clinical"]
        )
        # drop anywhere wins overall
        [result] = deidentify(
            {**payload, "policy": {"contact": "redact", "clinical": "drop"}}
        )
        self.assertNotIn("id_card", result["record"])
        [t] = result["transformations"]
        self.assertEqual(t["action"], "drop")

    def test_drop_array_element_becomes_null_and_containers_stay(self):
        [result] = deidentify(
            {
                "records": [
                    {
                        "phones": ["13800138000", "13900139000"],
                        "patient": {"name": "张三"},
                    }
                ],
                "policy": {"contact": "drop", "direct_identifier": "drop"},
            }
        )
        self.assertEqual(result["record"]["phones"], [None, None])
        self.assertEqual(result["record"]["patient"], {})  # empty parent kept

    def test_transformations_sorted_and_value_free(self):
        [result] = deidentify(
            {
                "records": [{"b": "x@y.com", "a": "13800138000", "c": {"id": VALID_ID}}],
                "policy": {"contact": "redact", "direct_identifier": "redact"},
            }
        )
        paths = [t["path"] for t in result["transformations"]]
        self.assertEqual(paths, sorted(paths))
        for t in result["transformations"]:
            self.assertEqual(set(t), {"path", "action", "categories"})
        blob = json.dumps(result, ensure_ascii=False)
        self.assertNotIn("x@y.com", blob)
        self.assertNotIn("13800138000", blob)
        self.assertNotIn(VALID_ID, blob)

    def test_schema_rules_apply(self):
        [result] = deidentify(
            {
                "records": [{"note": "hello", "other": "world"}],
                "schema": {"/note": "clinical"},
                "policy": {"clinical": "redact"},
            }
        )
        self.assertIsNone(result["record"]["note"])
        self.assertEqual(result["record"]["other"], "world")

    def test_results_follow_input_order(self):
        results = deidentify(
            {
                "records": [{"name": "a"}, {"foo": "bar"}, {"email": "a@b.com"}],
                "policy": {"direct_identifier": "drop", "contact": "redact"},
            }
        )
        self.assertEqual([r["index"] for r in results], [0, 1, 2])
        self.assertEqual(results[1]["record"], {"foo": "bar"})
        self.assertEqual(results[1]["transformations"], [])

    def test_caller_data_not_mutated_and_deterministic(self):
        payload = {
            "records": [{"name": "张三", "phones": ["13800138000"]}],
            "policy": {"direct_identifier": "drop", "contact": "drop"},
        }
        snapshot = copy.deepcopy(payload)
        first = deidentify(payload)
        second = deidentify(payload)
        self.assertEqual(payload, snapshot)
        self.assertEqual(first, second)


class PolicyValidationTest(unittest.TestCase):
    def test_invalid_policy(self):
        bad = [
            "redact",
            [],
            {},
            {"unknown": "keep"},
            {"contact": "hide"},
            {"contact": ["redact"]},
            {"contact": None},
            {"contact": "redact", "bogus": "keep"},
        ]
        for policy in bad:
            with self.subTest(policy=policy):
                with self.assertRaises(InvalidPolicy):
                    deidentify({"records": [{}], "policy": policy})

    def test_missing_policy_is_invalid_request(self):
        with self.assertRaises(InvalidRequest):
            deidentify({"records": [{}]})

    def test_invalid_request(self):
        bad = [
            None,
            [],
            "x",
            {},
            {"records": None, "policy": {"contact": "keep"}},
            {"records": [], "policy": {"contact": "keep"}},
            {"records": [1], "policy": {"contact": "keep"}},
        ]
        for payload in bad:
            with self.subTest(payload=payload):
                with self.assertRaises(InvalidRequest):
                    deidentify(payload)

    def test_invalid_schema(self):
        with self.assertRaises(InvalidSchema):
            deidentify(
                {
                    "records": [{}],
                    "schema": {"/x": "nope"},
                    "policy": {"contact": "keep"},
                }
            )


class DeidentifyHttpTest(unittest.TestCase):
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
        allow = resp.getheader("Allow")
        conn.close()
        return resp.status, json.loads(raw), allow

    def post(self, payload, content_type="application/json"):
        body = payload if isinstance(payload, (str, bytes)) else json.dumps(payload)
        return self.request("POST", "/v1/deidentify", body=body, content_type=content_type)

    def test_happy_path(self):
        status, payload, _ = self.post(
            {
                "records": [{"name": "张三", "contact": {"phone": "13800138000"}}],
                "policy": {"direct_identifier": "drop", "contact": "redact"},
            }
        )
        self.assertEqual(status, 200)
        [result] = payload["results"]
        self.assertEqual(result["index"], 0)
        self.assertEqual(result["record"], {"contact": {"phone": None}})
        blob = json.dumps(payload, ensure_ascii=False)
        self.assertNotIn("张三", blob)
        self.assertNotIn("13800138000", blob)

    def test_method_not_allowed(self):
        for method in ("GET", "PUT", "DELETE", "PATCH"):
            with self.subTest(method=method):
                status, payload, allow = self.request(method, "/v1/deidentify")
                self.assertEqual(status, 405)
                self.assertEqual(payload["error"]["code"], "method_not_allowed")
                self.assertEqual(allow, "POST")

    def test_unsupported_media_type(self):
        status, payload, _ = self.post(
            {"records": [{}], "policy": {"contact": "keep"}}, content_type="text/plain"
        )
        self.assertEqual(status, 415)
        self.assertEqual(payload["error"]["code"], "unsupported_media_type")

    def test_invalid_json(self):
        status, payload, _ = self.post("{not json")
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"]["code"], "invalid_json")

    def test_invalid_request(self):
        for body in ("[]", "{}", '{"records": []}', '{"records": [{}]}'):
            with self.subTest(body=body):
                status, payload, _ = self.post(body)
                self.assertEqual(status, 422)
                self.assertEqual(payload["error"]["code"], "invalid_request")

    def test_invalid_schema(self):
        status, payload, _ = self.post(
            {"records": [{}], "schema": "bad", "policy": {"contact": "keep"}}
        )
        self.assertEqual(status, 422)
        self.assertEqual(payload["error"]["code"], "invalid_schema")

    def test_invalid_policy(self):
        for policy in ('"redact"', "[]", "{}", '{"unknown": "keep"}', '{"contact": ["redact"]}'):
            with self.subTest(policy=policy):
                status, payload, _ = self.post(
                    '{"records": [{"id": "secret"}], "policy": %s}' % policy
                )
                self.assertEqual(status, 422)
                self.assertEqual(payload["error"]["code"], "invalid_policy")
                self.assertNotIn("secret", json.dumps(payload))


if __name__ == "__main__":
    unittest.main()
