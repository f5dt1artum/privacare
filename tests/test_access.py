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
    grant = {
        "grant_id": "g-1",
        "principal_id": "dr-1",
        "resource": "patient-records",
        "purpose": "treatment",
        "operations": ["read"],
        "data_categories": ["clinical"],
        "field_scopes": ["/diagnosis"],
    }
    grant.update(overrides)
    return grant


def make_access(**overrides):
    access = {
        "principal_id": "dr-1",
        "resource": "patient-records",
        "purpose": "treatment",
        "operation": "read",
        "data_categories": ["clinical"],
        "fields": ["/diagnosis"],
    }
    access.update(overrides)
    return access


class AccessEvaluateHttpTest(HttpTestBase):
    def post(self, payload, content_type="application/json"):
        body = payload if isinstance(payload, (str, bytes)) else json.dumps(payload)
        return self.request("POST", "/v1/access/evaluate", body=body, content_type=content_type)

    def test_grant_and_deny(self):
        status, payload = self.post(
            {
                "grants": [make_grant()],
                "accesses": [
                    make_access(),
                    make_access(principal_id="dr-2"),
                    make_access(resource="billing"),
                    make_access(purpose="research"),
                    make_access(operation="delete"),
                    make_access(data_categories=["contact"]),
                    make_access(fields=["/notes"]),
                ],
            }
        )
        self.assertEqual(status, 200)
        results = payload["results"]
        self.assertEqual([r["index"] for r in results], list(range(7)))
        self.assertEqual(
            results[0],
            {"index": 0, "allowed": True, "reason": "access_granted", "grant_id": "g-1"},
        )
        for result in results[1:]:
            self.assertEqual(result["allowed"], False)
            self.assertEqual(result["reason"], "no_matching_grant")
            self.assertNotIn("grant_id", result)

    def test_field_descendant_and_equality(self):
        status, payload = self.post(
            {
                "grants": [make_grant(field_scopes=["/record", "/exact"])],
                "accesses": [
                    make_access(fields=["/record"]),
                    make_access(fields=["/record/diagnosis"]),
                    make_access(fields=["/record/diagnosis/0/code"]),
                    make_access(fields=["/exact"]),
                    make_access(fields=["/exactness"]),
                    make_access(fields=["/record", "/other"]),
                ],
            }
        )
        self.assertEqual(status, 200)
        self.assertEqual(
            [r["allowed"] for r in payload["results"]],
            [True, True, True, True, False, False],
        )

    def test_pointer_segments_not_string_prefix(self):
        # "/ab" is not a descendant of "/a"; segment "/a~1b" differs from "/a/b".
        status, payload = self.post(
            {
                "grants": [make_grant(field_scopes=["/a"])],
                "accesses": [
                    make_access(fields=["/ab"]),
                    make_access(fields=["/a/b"]),
                ],
            }
        )
        self.assertEqual(status, 200)
        self.assertEqual([r["allowed"] for r in payload["results"]], [False, True])

    def test_escaped_segments(self):
        status, payload = self.post(
            {
                "grants": [make_grant(field_scopes=["/a~1b", "/m~0n"])],
                "accesses": [
                    make_access(fields=["/a~1b/c"]),
                    make_access(fields=["/m~0n"]),
                    make_access(fields=["/a/b"]),
                ],
            }
        )
        self.assertEqual(status, 200)
        self.assertEqual([r["allowed"] for r in payload["results"]], [True, True, False])

    def test_categories_must_be_subset(self):
        status, payload = self.post(
            {
                "grants": [make_grant(data_categories=["clinical", "contact"])],
                "accesses": [
                    make_access(data_categories=["clinical"]),
                    make_access(data_categories=["clinical", "contact"]),
                    make_access(data_categories=["clinical", "financial"]),
                ],
            }
        )
        self.assertEqual(status, 200)
        self.assertEqual([r["allowed"] for r in payload["results"]], [True, True, False])

    def test_grants_are_not_combined(self):
        # Each grant covers part of the access; none covers it alone.
        status, payload = self.post(
            {
                "grants": [
                    make_grant(grant_id="g-a", field_scopes=["/a"]),
                    make_grant(grant_id="g-b", field_scopes=["/b"]),
                ],
                "accesses": [make_access(fields=["/a", "/b"])],
            }
        )
        self.assertEqual(status, 200)
        self.assertEqual(payload["results"][0]["allowed"], False)
        self.assertEqual(payload["results"][0]["reason"], "no_matching_grant")

    def test_smallest_grant_id_wins(self):
        status, payload = self.post(
            {
                "grants": [
                    make_grant(grant_id="g-b"),
                    make_grant(grant_id="g-a"),
                    make_grant(grant_id="g-c", field_scopes=["/other"]),
                ],
                "accesses": [make_access()],
            }
        )
        self.assertEqual(status, 200)
        self.assertEqual(payload["results"][0]["grant_id"], "g-a")

    def test_all_operations(self):
        status, payload = self.post(
            {
                "grants": [make_grant(operations=["read", "update", "export", "delete"])],
                "accesses": [
                    make_access(operation="read"),
                    make_access(operation="update"),
                    make_access(operation="export"),
                    make_access(operation="delete"),
                ],
            }
        )
        self.assertEqual(status, 200)
        self.assertEqual([r["allowed"] for r in payload["results"]], [True] * 4)

    def test_no_echo_and_no_mutation_and_deterministic(self):
        payload = {
            "grants": [make_grant(), make_grant(grant_id="g-2", operations=["delete"])],
            "accesses": [make_access(), make_access(purpose="research")],
        }
        snapshot = copy.deepcopy(payload)
        status, first = self.post(payload)
        self.assertEqual(status, 200)
        self.assertEqual(payload, snapshot)
        status, second = self.post(payload)
        self.assertEqual(status, 200)
        self.assertEqual(first, second)
        # 响应不回显输入的主体、资源、用途或字段取值
        body = json.dumps(first)
        self.assertNotIn("dr-1", body)
        self.assertNotIn("patient-records", body)
        self.assertNotIn("treatment", body)
        self.assertNotIn("diagnosis", body)

    def test_invalid_request(self):
        for body in (
            "[]",
            "{}",
            '{"grants": []}',
            '{"accesses": []}',
            '{"grants": [], "accesses": [{}]}',
            '{"grants": [{}], "accesses": []}',
            '{"grants": {}, "accesses": [{}]}',
            '"text"',
        ):
            with self.subTest(body=body):
                status, payload = self.post(body)
                self.assertEqual(status, 422)
                self.assertEqual(payload["error"]["code"], "invalid_request")

    def test_invalid_grant(self):
        base = make_grant()
        cases = []
        for field in (
            "grant_id",
            "principal_id",
            "resource",
            "purpose",
            "operations",
            "data_categories",
            "field_scopes",
        ):
            broken = {k: v for k, v in base.items() if k != field}
            cases.append(broken)
        cases += [
            "not-an-object",
            make_grant(grant_id=""),
            make_grant(principal_id=""),
            make_grant(resource=""),
            make_grant(purpose=""),
            make_grant(operations=[]),
            make_grant(operations=["read", "read"]),
            make_grant(operations=["read", 1]),
            make_grant(operations=["admin"]),
            make_grant(data_categories=[]),
            make_grant(data_categories=["clinical", "clinical"]),
            make_grant(data_categories=["unknown"]),
            make_grant(field_scopes=[]),
            make_grant(field_scopes=["/a", "/a"]),
            make_grant(field_scopes=["a"]),
            make_grant(field_scopes=["/a~2b"]),
            make_grant(field_scopes=["/a~"]),
            make_grant(field_scopes=[1]),
        ]
        for grant in cases:
            with self.subTest(grant=grant):
                status, payload = self.post(
                    {"grants": [grant], "accesses": [make_access()]}
                )
                self.assertEqual(status, 422)
                self.assertEqual(payload["error"]["code"], "invalid_grant")

    def test_duplicate_grant_id(self):
        status, payload = self.post(
            {
                "grants": [make_grant(), make_grant(principal_id="dr-2")],
                "accesses": [make_access()],
            }
        )
        self.assertEqual(status, 422)
        self.assertEqual(payload["error"]["code"], "invalid_grant")

    def test_invalid_access(self):
        base = make_access()
        cases = []
        for field in (
            "principal_id",
            "resource",
            "purpose",
            "operation",
            "data_categories",
            "fields",
        ):
            broken = {k: v for k, v in base.items() if k != field}
            cases.append(broken)
        cases += [
            "not-an-object",
            make_access(principal_id=""),
            make_access(resource=""),
            make_access(purpose=""),
            make_access(operation=""),
            make_access(operation="admin"),
            make_access(data_categories=[]),
            make_access(data_categories=["clinical", "clinical"]),
            make_access(data_categories=["unknown"]),
            make_access(fields=[]),
            make_access(fields=["/a", "/a"]),
            make_access(fields=["a"]),
            make_access(fields=["/a~2b"]),
        ]
        for access in cases:
            with self.subTest(access=access):
                status, payload = self.post(
                    {"grants": [make_grant()], "accesses": [access]}
                )
                self.assertEqual(status, 422)
                self.assertEqual(payload["error"]["code"], "invalid_access")

    def test_empty_pointer_is_valid_and_covers_everything(self):
        status, payload = self.post(
            {
                "grants": [make_grant(field_scopes=[""])],
                "accesses": [
                    make_access(fields=["/anything/at/all"]),
                    make_access(fields=[""]),
                ],
            }
        )
        self.assertEqual(status, 200)
        self.assertEqual([r["allowed"] for r in payload["results"]], [True, True])

    def test_no_partial_results_on_any_failure(self):
        status, payload = self.post(
            {
                "grants": [make_grant()],
                "accesses": [make_access(), make_access(operation="admin")],
            }
        )
        self.assertEqual(status, 422)
        self.assertNotIn("results", payload)

    def test_unsupported_media_type(self):
        status, payload = self.post(
            {"grants": [make_grant()], "accesses": [make_access()]},
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
                status, payload = self.request(method, "/v1/access/evaluate")
                self.assertEqual(status, 405)
                self.assertEqual(payload["error"]["code"], "method_not_allowed")

    def test_unknown_path_404(self):
        status, payload = self.request("POST", "/v1/access")
        self.assertEqual(status, 404)
        self.assertEqual(payload["error"]["code"], "not_found")


if __name__ == "__main__":
    unittest.main()
