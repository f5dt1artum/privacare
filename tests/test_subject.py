import copy
import http.client
import json
import threading
import unittest
from http.server import ThreadingHTTPServer

from privacare.server import Handler

PATH = "/v1/subject-requests/process"


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

    def post(self, payload, content_type="application/json"):
        body = payload if isinstance(payload, (str, bytes)) else json.dumps(payload)
        return self.request("POST", PATH, body=body, content_type=content_type)


def make_records():
    return [
        {"record_id": "r-2", "subject_id": "s-1", "data": {"name": "甲", "tags": ["a", "b"]}},
        {"record_id": "r-1", "subject_id": "s-1", "data": {"name": "乙", "note": {"x": 1}}},
        {"record_id": "r-3", "subject_id": "s-2", "data": {"name": "丙"}},
    ]


def make_request(request_id, subject_id="s-1", type="export", verified=True, **extra):
    request = {
        "request_id": request_id,
        "subject_id": subject_id,
        "type": type,
        "verified": verified,
    }
    request.update(extra)
    return request


class SubjectRequestHappyPathTest(HttpTestBase):
    def test_export_returns_sorted_records(self):
        status, payload = self.post(
            {"records": make_records(), "requests": [make_request("q-1")]}
        )
        self.assertEqual(status, 200)
        result = payload["results"][0]
        self.assertEqual(result["request_id"], "q-1")
        self.assertEqual(result["status"], "exported")
        self.assertEqual(
            result["records"],
            [
                {"record_id": "r-1", "data": {"name": "乙", "note": {"x": 1}}},
                {"record_id": "r-2", "data": {"name": "甲", "tags": ["a", "b"]}},
            ],
        )
        self.assertEqual([r["record_id"] for r in payload["records"]], ["r-2", "r-1", "r-3"])

    def test_export_without_match_returns_empty_array(self):
        status, payload = self.post(
            {"records": make_records(), "requests": [make_request("q-1", subject_id="s-9")]}
        )
        self.assertEqual(status, 200)
        self.assertEqual(payload["results"][0]["records"], [])

    def test_unverified_request_is_rejected_and_changes_nothing(self):
        status, payload = self.post(
            {
                "records": make_records(),
                "requests": [make_request("q-1", type="delete", verified=False)],
            }
        )
        self.assertEqual(status, 200)
        self.assertEqual(
            payload["results"][0],
            {"request_id": "q-1", "status": "rejected", "reason": "identity_not_verified"},
        )
        self.assertEqual(len(payload["records"]), 3)

    def test_delete_removes_all_subject_records(self):
        status, payload = self.post(
            {
                "records": make_records(),
                "requests": [
                    make_request("q-1", type="delete"),
                    make_request("q-2", type="delete"),
                ],
            }
        )
        self.assertEqual(status, 200)
        first, second = payload["results"]
        self.assertEqual(first["status"], "deleted")
        self.assertEqual(first["deleted_count"], 2)
        self.assertEqual(first["record_ids"], ["r-1", "r-2"])
        self.assertEqual(second["deleted_count"], 0)
        self.assertEqual(second["record_ids"], [])
        self.assertEqual([r["record_id"] for r in payload["records"]], ["r-3"])

    def test_correct_updates_existing_locations(self):
        status, payload = self.post(
            {
                "records": make_records(),
                "requests": [
                    make_request(
                        "q-1",
                        type="correct",
                        changes=[
                            {"record_id": "r-2", "path": "/tags/1", "value": "z"},
                            {"record_id": "r-1", "path": "/note/x", "value": None},
                            {"record_id": "r-2", "path": "/name", "value": "丁"},
                        ],
                    )
                ],
            }
        )
        self.assertEqual(status, 200)
        result = payload["results"][0]
        self.assertEqual(result["status"], "corrected")
        self.assertEqual(
            result["changes"],
            [
                {"record_id": "r-1", "path": "/note/x"},
                {"record_id": "r-2", "path": "/name"},
                {"record_id": "r-2", "path": "/tags/1"},
            ],
        )
        final = {r["record_id"]: r["data"] for r in payload["records"]}
        self.assertEqual(final["r-1"], {"name": "乙", "note": {"x": None}})
        self.assertEqual(final["r-2"], {"name": "丁", "tags": ["a", "z"]})
        self.assertEqual(final["r-3"], {"name": "丙"})

    def test_requests_apply_in_order(self):
        status, payload = self.post(
            {
                "records": make_records(),
                "requests": [
                    make_request(
                        "q-1",
                        type="correct",
                        changes=[{"record_id": "r-1", "path": "/name", "value": "改"}],
                    ),
                    make_request("q-2"),
                    make_request("q-3", type="delete"),
                    make_request("q-4"),
                ],
            }
        )
        self.assertEqual(status, 200)
        self.assertEqual([r["request_id"] for r in payload["results"]], ["q-1", "q-2", "q-3", "q-4"])
        exported_before = payload["results"][1]["records"]
        self.assertEqual(
            [r["record_id"] for r in exported_before],
            ["r-1", "r-2"],
        )
        self.assertEqual(exported_before[0]["data"]["name"], "改")
        self.assertEqual(payload["results"][3]["records"], [])
        self.assertEqual([r["record_id"] for r in payload["records"]], ["r-3"])

    def test_input_payload_is_not_mutated(self):
        body = {
            "records": make_records(),
            "requests": [
                make_request(
                    "q-1",
                    type="correct",
                    changes=[{"record_id": "r-1", "path": "/name", "value": "改"}],
                ),
                make_request("q-2", type="delete"),
            ],
        }
        snapshot = copy.deepcopy(body)
        status, _ = self.post(body)
        self.assertEqual(status, 200)
        self.assertEqual(body, snapshot)


class SubjectRequestHttpSemanticsTest(HttpTestBase):
    def test_get_is_405(self):
        status, payload = self.request("GET", PATH)
        self.assertEqual(status, 405)
        self.assertEqual(payload["error"]["code"], "method_not_allowed")

    def test_unknown_path_is_404(self):
        status, payload = self.request("POST", "/v1/subject-requests")
        self.assertEqual(status, 404)
        self.assertEqual(payload["error"]["code"], "not_found")

    def test_unsupported_media_type(self):
        status, payload = self.post("{}", content_type="text/plain")
        self.assertEqual(status, 415)
        self.assertEqual(payload["error"]["code"], "unsupported_media_type")

    def test_invalid_json(self):
        status, payload = self.post("{not json")
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"]["code"], "invalid_json")


class SubjectRequestValidationTest(HttpTestBase):
    def assert_error(self, payload, code):
        status, body = self.post(payload)
        self.assertEqual(status, 422)
        self.assertEqual(body["error"]["code"], code)

    def test_invalid_request(self):
        self.assert_error([], "invalid_request")
        self.assert_error({"requests": [make_request("q-1")]}, "invalid_request")
        self.assert_error({"records": make_records()}, "invalid_request")
        self.assert_error({"records": [], "requests": [make_request("q-1")]}, "invalid_request")

    def test_invalid_record(self):
        requests = [make_request("q-1")]
        self.assert_error({"records": [{}], "requests": requests}, "invalid_record")
        self.assert_error(
            {"records": [{"record_id": "r", "subject_id": "s", "data": []}], "requests": requests},
            "invalid_record",
        )
        duplicate = make_records()[:1] + make_records()[:1]
        self.assert_error({"records": duplicate, "requests": requests}, "invalid_record")

    def test_invalid_subject_request(self):
        records = make_records()
        self.assert_error({"records": records, "requests": [{}]}, "invalid_subject_request")
        self.assert_error(
            {"records": records, "requests": [make_request("q-1", type="view")]},
            "invalid_subject_request",
        )
        self.assert_error(
            {"records": records, "requests": [make_request("q-1", verified="yes")]},
            "invalid_subject_request",
        )
        self.assert_error(
            {"records": records, "requests": [make_request("q-1"), make_request("q-1")]},
            "invalid_subject_request",
        )
        self.assert_error(
            {"records": records, "requests": [make_request("q-1", changes=[])]},
            "invalid_subject_request",
        )
        self.assert_error(
            {"records": records, "requests": [make_request("q-1", type="delete", changes=[])]},
            "invalid_subject_request",
        )
        self.assert_error(
            {"records": records, "requests": [make_request("q-1", type="correct")]},
            "invalid_subject_request",
        )
        self.assert_error(
            {"records": records, "requests": [make_request("q-1", type="correct", changes=[])]},
            "invalid_subject_request",
        )

    def test_invalid_correction(self):
        records = make_records()

        def correct(changes):
            return {"records": records, "requests": [make_request("q-1", type="correct", changes=changes)]}

        self.assert_error(correct([{"record_id": "r-1", "path": "/name"}]), "invalid_correction")
        self.assert_error(
            correct([{"record_id": "r-1", "path": "", "value": 1}]), "invalid_correction"
        )
        self.assert_error(
            correct([{"record_id": "r-1", "path": "name", "value": 1}]), "invalid_correction"
        )
        self.assert_error(
            correct([{"record_id": "r-1", "path": "/na~2me", "value": 1}]), "invalid_correction"
        )
        # 同记录路径重复或互为祖先
        self.assert_error(
            correct(
                [
                    {"record_id": "r-1", "path": "/note", "value": 1},
                    {"record_id": "r-1", "path": "/note/x", "value": 2},
                ]
            ),
            "invalid_correction",
        )
        self.assert_error(
            correct(
                [
                    {"record_id": "r-1", "path": "/name", "value": 1},
                    {"record_id": "r-1", "path": "/name", "value": 2},
                ]
            ),
            "invalid_correction",
        )
        # 动态目标：记录当时不存在（已被先前请求删除）
        self.assert_error(
            {
                "records": records,
                "requests": [
                    make_request("q-1", type="delete"),
                    make_request(
                        "q-2",
                        type="correct",
                        changes=[{"record_id": "r-1", "path": "/name", "value": 1}],
                    ),
                ],
            },
            "invalid_correction",
        )
        # 主体归属
        self.assert_error(
            correct([{"record_id": "r-3", "path": "/name", "value": 1}]), "invalid_correction"
        )
        # 既有路径
        self.assert_error(
            correct([{"record_id": "r-1", "path": "/missing", "value": 1}]), "invalid_correction"
        )
        self.assert_error(
            correct([{"record_id": "r-2", "path": "/tags/2", "value": 1}]), "invalid_correction"
        )
        self.assert_error(
            correct([{"record_id": "r-2", "path": "/tags/01", "value": 1}]), "invalid_correction"
        )
        self.assert_error(
            correct([{"record_id": "r-2", "path": "/tags/-", "value": 1}]), "invalid_correction"
        )
        self.assert_error(
            correct([{"record_id": "r-1", "path": "/name/x", "value": 1}]), "invalid_correction"
        )

    def test_failed_request_returns_no_partial_results(self):
        status, payload = self.post(
            {
                "records": make_records(),
                "requests": [
                    make_request("q-1", type="delete"),
                    make_request("q-2", type="correct", changes=[{"record_id": "r-1"}]),
                ],
            }
        )
        self.assertEqual(status, 422)
        self.assertNotIn("results", payload)


if __name__ == "__main__":
    unittest.main()
