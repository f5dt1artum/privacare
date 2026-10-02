import http.client
import json
import threading
import unittest
from http.server import ThreadingHTTPServer

from privacare import __version__
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


class ClassifyHttpTest(HttpTestBase):
    def post(self, payload, content_type="application/json"):
        body = payload if isinstance(payload, (str, bytes)) else json.dumps(payload)
        return self.request("POST", "/v1/classify", body=body, content_type=content_type)

    def test_healthz_unchanged(self):
        status, payload = self.request("GET", "/healthz")
        self.assertEqual(status, 200)
        self.assertEqual(
            payload,
            {"status": "ok", "service": "privacare", "version": __version__},
        )

    def test_unknown_path_404(self):
        status, payload = self.request("GET", "/nope")
        self.assertEqual(status, 404)
        self.assertEqual(payload["error"]["code"], "not_found")

    def test_classify_happy_path(self):
        status, payload = self.post(
            {
                "records": [
                    {"name": "张三", "contact": {"phone": "13800138000"}},
                    {"note": "nothing"},
                ],
                "schema": {"/note": "clinical"},
            }
        )
        self.assertEqual(status, 200)
        results = payload["results"]
        self.assertEqual([r["index"] for r in results], [0, 1])
        fields = {f["path"]: f for f in results[0]["fields"]}
        self.assertEqual(fields["/name"]["categories"], ["direct_identifier"])
        self.assertEqual(fields["/contact/phone"]["categories"], ["contact"])
        self.assertEqual(fields["/contact/phone"]["sources"], ["field_name", "value"])
        self.assertEqual(
            results[1]["fields"],
            [{"categories": ["clinical"], "path": "/note", "sources": ["schema"]}],
        )
        # 原始值不得回显
        self.assertNotIn("张三", json.dumps(payload, ensure_ascii=False))
        self.assertNotIn("13800138000", json.dumps(payload))

    def test_unsupported_media_type(self):
        status, payload = self.post({"records": [{}]}, content_type="text/plain")
        self.assertEqual(status, 415)
        self.assertEqual(payload["error"]["code"], "unsupported_media_type")

    def test_missing_content_type(self):
        status, payload = self.request("POST", "/v1/classify", body="{}")
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

    def test_invalid_schema(self):
        status, payload = self.post({"records": [{}], "schema": {"/x": "nope"}})
        self.assertEqual(status, 422)
        self.assertEqual(payload["error"]["code"], "invalid_schema")

    def test_method_not_allowed(self):
        for method in ("GET", "PUT", "DELETE", "PATCH"):
            with self.subTest(method=method):
                status, payload = self.request(method, "/v1/classify")
                self.assertEqual(status, 405)
                self.assertEqual(payload["error"]["code"], "method_not_allowed")

    def test_error_body_has_no_sensitive_values(self):
        secret = "11010519491231002X"
        status, payload = self.post({"records": [{"id": secret}], "schema": "bad"})
        self.assertEqual(status, 422)
        self.assertNotIn(secret, json.dumps(payload))


if __name__ == "__main__":
    unittest.main()
