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


def deidentify(payload):
    return Service().deidentify(payload)


def base_payload(**overrides):
    payload = {
        "records": [
            {
                "name": "张三",
                "age": 45,
                "contact": {"phone": "13800138000", "email": "a@b.com"},
                "tags": ["x@y.com", "plain"],
                "note": "nothing",
            }
        ],
        "policy": {"direct_identifier": "drop", "contact": "redact"},
    }
    payload.update(overrides)
    return payload


class DeidentifyTransformTest(unittest.TestCase):
    def test_drop_redact_keep(self):
        [result] = deidentify(base_payload())
        self.assertEqual(result["index"], 0)
        record = result["record"]
        # drop removes the object member entirely
        self.assertNotIn("name", record)
        # redact replaces values with None, keeping containers
        self.assertEqual(record["contact"], {"phone": None, "email": None})
        # array elements become None rather than being removed
        self.assertEqual(record["tags"], [None, "plain"])
        # unconfigured categories (quasi_identifier) and unmatched leaves stay
        self.assertEqual(record["age"], 45)
        self.assertEqual(record["note"], "nothing")

    def test_transformations_listing(self):
        [result] = deidentify(base_payload())
        transformations = result["transformations"]
        paths = [t["path"] for t in transformations]
        self.assertEqual(paths, sorted(paths))
        self.assertEqual(
            paths,
            ["/contact/email", "/contact/phone", "/name", "/tags/0"],
        )
        by_path = {t["path"]: t for t in transformations}
        self.assertEqual(by_path["/name"]["action"], "drop")
        self.assertEqual(by_path["/name"]["categories"], ["direct_identifier"])
        self.assertEqual(by_path["/contact/phone"]["action"], "redact")
        self.assertEqual(by_path["/contact/phone"]["categories"], ["contact"])
        self.assertEqual(by_path["/tags/0"]["action"], "redact")
        for item in transformations:
            self.assertEqual(set(item), {"path", "action", "categories"})
        # 清单与结果都不得回显原始值
        import json

        blob = json.dumps(result, ensure_ascii=False)
        self.assertNotIn("张三", blob)
        self.assertNotIn("13800138000", blob)
        self.assertNotIn("a@b.com", blob)

    def test_action_priority_drop_over_redact_over_keep(self):
        payload = base_payload(
            schema={"/note": ["clinical", "financial"]},
            policy={"clinical": "keep", "financial": "redact", "contact": "drop"},
        )
        [result] = deidentify(payload)
        by_path = {t["path"]: t for t in result["transformations"]}
        # /note hits clinical(keep) + financial(redact) -> redact
        self.assertEqual(by_path["/note"]["action"], "redact")
        self.assertEqual(by_path["/note"]["categories"], ["clinical", "financial"])
        # contact leaves hit contact(drop) -> removed/nulled
        self.assertNotIn("phone", result["record"]["contact"])
        self.assertEqual(result["record"]["tags"], [None, "plain"])

    def test_drop_wins_over_redact(self):
        payload = base_payload(
            records=[{"id": VALID_ID}],
            schema={"/id": "financial"},
            policy={"direct_identifier": "redact", "financial": "drop"},
        )
        [result] = deidentify(payload)
        self.assertEqual(result["record"], {})
        [t] = result["transformations"]
        self.assertEqual(t["action"], "drop")
        self.assertEqual(t["categories"], ["direct_identifier", "financial"])

    def test_empty_parent_container_retained(self):
        payload = base_payload(
            records=[{"contact": {"phone": "13800138000"}}],
            policy={"contact": "drop"},
        )
        [result] = deidentify(payload)
        self.assertEqual(result["record"], {"contact": {}})

    def test_keep_not_listed(self):
        payload = base_payload(policy={"direct_identifier": "keep", "contact": "keep"})
        [result] = deidentify(payload)
        self.assertEqual(result["transformations"], [])
        self.assertEqual(result["record"]["name"], "张三")

    def test_results_order_and_index(self):
        payload = base_payload(
            records=[{"name": "张三"}, {"note": "x"}, {"age": 3}],
            policy={"direct_identifier": "drop"},
        )
        results = deidentify(payload)
        self.assertEqual([r["index"] for r in results], [0, 1, 2])
        self.assertEqual(results[0]["record"], {})
        self.assertEqual(results[1]["record"], {"note": "x"})
        self.assertEqual(results[1]["transformations"], [])

    def test_input_not_mutated_and_deterministic(self):
        payload = base_payload()
        snapshot = copy.deepcopy(payload)
        first = deidentify(payload)
        second = deidentify(payload)
        self.assertEqual(payload, snapshot)
        self.assertEqual(first, second)

    def test_schema_drives_transformations(self):
        payload = base_payload(
            records=[{"custom": {"deep": "value"}}],
            schema={"/custom": "clinical"},
            policy={"clinical": "redact"},
        )
        [result] = deidentify(payload)
        self.assertEqual(result["record"], {"custom": {"deep": None}})
        self.assertEqual(
            result["transformations"],
            [{"path": "/custom/deep", "action": "redact", "categories": ["clinical"]}],
        )


class DeidentifyValidationTest(unittest.TestCase):
    def test_invalid_request(self):
        bad = [
            None,
            [],
            "x",
            {},
            {"records": None},
            {"records": []},
            {"records": [1]},
            {"records": [{}]},  # missing policy
            {"records": [{}], "schema": {}},
        ]
        for payload in bad:
            with self.subTest(payload=payload):
                with self.assertRaises(InvalidRequest):
                    deidentify(payload)

    def test_invalid_schema(self):
        with self.assertRaises(InvalidSchema):
            deidentify({"records": [{}], "policy": {"clinical": "keep"}, "schema": "bad"})
        with self.assertRaises(InvalidSchema):
            deidentify(
                {"records": [{}], "policy": {"clinical": "keep"}, "schema": {"/x": "nope"}}
            )

    def test_invalid_policy(self):
        bad_policies = [
            None,
            "redact",
            ["redact"],
            {},
            {"clinical": "mask"},
            {"clinical": ["drop"]},
            {"clinical": None},
            {"unknown_category": "drop"},
            {"clinical": "drop", "email": "keep"},
        ]
        for policy in bad_policies:
            with self.subTest(policy=policy):
                with self.assertRaises(InvalidPolicy):
                    deidentify({"records": [{}], "policy": policy})

    def test_policy_not_leaked_across_calls(self):
        service = Service()
        service.deidentify({"records": [{"name": "张三"}], "policy": {"direct_identifier": "drop"}})
        [result] = service.deidentify(
            {"records": [{"name": "张三"}], "policy": {"direct_identifier": "keep"}}
        )
        self.assertEqual(result["record"], {"name": "张三"})


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
        status, parsed, _allow = self.request(
            "POST", "/v1/deidentify", body=body, content_type=content_type
        )
        return status, parsed

    def test_happy_path(self):
        status, payload = self.post(
            {
                "records": [{"name": "张三", "contact": {"phone": "13800138000"}}],
                "policy": {"direct_identifier": "drop", "contact": "redact"},
            }
        )
        self.assertEqual(status, 200)
        [result] = payload["results"]
        self.assertEqual(result["index"], 0)
        self.assertEqual(result["record"], {"contact": {"phone": None}})
        self.assertNotIn("张三", json.dumps(payload, ensure_ascii=False))
        self.assertNotIn("13800138000", json.dumps(payload))

    def test_unsupported_media_type(self):
        status, payload = self.post({"records": [{}], "policy": {}}, content_type="text/plain")
        self.assertEqual(status, 415)
        self.assertEqual(payload["error"]["code"], "unsupported_media_type")

    def test_invalid_json(self):
        status, payload = self.post("{not json")
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"]["code"], "invalid_json")

    def test_invalid_request(self):
        for body in ("[]", "{}", '{"records": []}', '{"records": [{}]}'):
            with self.subTest(body=body):
                status, payload = self.post(body)
                self.assertEqual(status, 422)
                self.assertEqual(payload["error"]["code"], "invalid_request")

    def test_invalid_schema(self):
        status, payload = self.post(
            {"records": [{}], "policy": {"clinical": "keep"}, "schema": {"/x": "nope"}}
        )
        self.assertEqual(status, 422)
        self.assertEqual(payload["error"]["code"], "invalid_schema")

    def test_invalid_policy(self):
        for policy in ('{}', '"redact"', '["drop"]', '{"clinical": "mask"}', '{"nope": "drop"}'):
            with self.subTest(policy=policy):
                status, payload = self.post('{"records": [{}], "policy": %s}' % policy)
                self.assertEqual(status, 422)
                self.assertEqual(payload["error"]["code"], "invalid_policy")

    def test_method_not_allowed(self):
        for method in ("GET", "PUT", "DELETE", "PATCH"):
            with self.subTest(method=method):
                status, payload, allow = self.request(method, "/v1/deidentify")
                self.assertEqual(status, 405)
                self.assertEqual(payload["error"]["code"], "method_not_allowed")
                self.assertEqual(allow, "POST")

    def test_error_body_has_no_sensitive_values(self):
        secret = "11010519491231002X"
        status, payload = self.post(
            {"records": [{"id": secret}], "policy": {"unknown": "drop"}}
        )
        self.assertEqual(status, 422)
        self.assertNotIn(secret, json.dumps(payload))


if __name__ == "__main__":
    unittest.main()
