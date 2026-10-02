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

    def request(self, method, path, body=None, content_type="application/json"):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        headers = {}
        if content_type is not None:
            headers["Content-Type"] = content_type
        conn.request(method, path, body=body, headers=headers)
        resp = conn.getresponse()
        payload = json.loads(resp.read())
        conn.close()
        return resp.status, payload


class ClassifyEndpointTest(HttpTestBase):
    def post(self, body, content_type="application/json"):
        raw = body if isinstance(body, (str, bytes)) else json.dumps(body)
        return self.request("POST", "/v1/classify", raw, content_type)

    def test_basic_classification(self):
        status, payload = self.post({
            "records": [
                {"姓名": "张三", "email": "a@b.com"},
                {"note": "无敏感字段"},
            ]
        })
        self.assertEqual(status, 200)
        results = payload["results"]
        self.assertEqual([r["index"] for r in results], [0, 1])
        first = {f["path"]: f for f in results[0]["fields"]}
        self.assertEqual(first["/姓名"]["categories"], ["direct_identifier"])
        self.assertEqual(first["/email"]["sources"], ["field_name", "value"])
        self.assertEqual(results[1]["fields"], [])

    def test_schema_applies_per_request(self):
        body = {"records": [{"code": "A01"}], "schema": {"/code": "clinical"}}
        status, payload = self.post(body)
        self.assertEqual(status, 200)
        fields = payload["results"][0]["fields"]
        self.assertEqual(
            fields,
            [{"path": "/code", "categories": ["clinical"], "sources": ["schema"]}],
        )
        # 第二次请求不带 schema, 不得残留规则
        status, payload = self.post({"records": [{"code": "A01"}]})
        self.assertEqual(status, 200)
        self.assertEqual(payload["results"][0]["fields"], [])

    def test_unsupported_media_type(self):
        status, payload = self.post("{}", content_type="text/plain")
        self.assertEqual(status, 415)
        self.assertEqual(payload["error"]["code"], "unsupported_media_type")

    def test_invalid_json(self):
        status, payload = self.post("{not json")
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"]["code"], "invalid_json")

    def test_invalid_request_shapes(self):
        for body in ([], {"records": []}, {"records": "x"}, {"records": [[1]]}):
            status, payload = self.post(body)
            self.assertEqual(status, 422, body)
            self.assertEqual(payload["error"]["code"], "invalid_request", body)

    def test_invalid_schema(self):
        cases = [
            {"records": [{"a": 1}], "schema": "nope"},
            {"records": [{"a": 1}], "schema": {"bad": "clinical"}},
            {"records": [{"a": 1}], "schema": {"/a": "unknown"}},
        ]
        for body in cases:
            status, payload = self.post(body)
            self.assertEqual(status, 422, body)
            self.assertEqual(payload["error"]["code"], "invalid_schema", body)

    def test_error_does_not_echo_sensitive_values(self):
        secret = "110101199003078877"
        status, payload = self.post(
            '{"records": [{"id": "%s"}], "schema": 1}' % secret
        )
        self.assertEqual(status, 422)
        self.assertNotIn(secret, json.dumps(payload))

    def test_method_not_allowed(self):
        for method in ("GET", "PUT", "DELETE", "PATCH"):
            status, payload = self.request(method, "/v1/classify")
            self.assertEqual(status, 405, method)
            self.assertEqual(payload["error"]["code"], "method_not_allowed", method)

    def test_healthz_unchanged(self):
        status, payload = self.request("GET", "/healthz")
        self.assertEqual(status, 200)
        self.assertEqual(payload["status"], "ok")
        self.assertEqual(payload["service"], "privacare")
        self.assertIn("version", payload)

    def test_unknown_path_404(self):
        status, payload = self.request("GET", "/nope")
        self.assertEqual(status, 404)
        self.assertEqual(payload["error"]["code"], "not_found")
        status, payload = self.request("POST", "/nope")
        self.assertEqual(status, 404)
        self.assertEqual(payload["error"]["code"], "not_found")


if __name__ == "__main__":
    unittest.main()
