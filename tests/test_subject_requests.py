import copy
import http.client
import json
import threading
import unittest
from http.server import ThreadingHTTPServer

from privacare.server import Handler
from privacare.service import Service
from privacare.subject_requests import (
    InvalidCorrection,
    InvalidRecord,
    InvalidSubjectRequest,
    process_subject_requests,
)
from privacare.classifier import InvalidRequest


def record(record_id, subject_id, data):
    return {"record_id": record_id, "subject_id": subject_id, "data": data}


def export_req(request_id, subject_id, verified=True, **extra):
    req = {
        "request_id": request_id,
        "subject_id": subject_id,
        "type": "export",
        "verified": verified,
    }
    req.update(extra)
    return req


def delete_req(request_id, subject_id, verified=True, **extra):
    req = {
        "request_id": request_id,
        "subject_id": subject_id,
        "type": "delete",
        "verified": verified,
    }
    req.update(extra)
    return req


def correct_req(request_id, subject_id, changes, verified=True):
    return {
        "request_id": request_id,
        "subject_id": subject_id,
        "type": "correct",
        "verified": verified,
        "changes": changes,
    }


def change(record_id, path, value):
    return {"record_id": record_id, "path": path, "value": value}


RECORDS = [
    record("r2", "s1", {"name": "old", "nested": {"b": 1}, "arr": [10, 20]}),
    record("r1", "s1", {"name": "first"}),
    record("r3", "s2", {"name": "other"}),
]


class SubjectRequestsTest(unittest.TestCase):
    def process(self, records=None, requests=None):
        return process_subject_requests(
            {"records": RECORDS if records is None else records, "requests": requests}
        )

    def test_export_sorted_by_record_id(self):
        out = self.process(requests=[export_req("q1", "s1")])
        self.assertEqual(
            out["results"][0]["records"],
            [
                {"record_id": "r1", "data": {"name": "first"}},
                {"record_id": "r2", "data": {"name": "old", "nested": {"b": 1}, "arr": [10, 20]}},
            ],
        )

    def test_export_no_match_is_empty(self):
        out = self.process(requests=[export_req("q1", "nobody")])
        self.assertEqual(out["results"][0]["records"], [])

    def test_unverified_rejected_leaves_records_unchanged(self):
        for rtype, kwargs in (
            ("export", {}),
            ("delete", {}),
            ("correct", {"changes": [change("r1", "/name", "x")]}),
        ):
            with self.subTest(type=rtype):
                req = {
                    "request_id": "q1",
                    "subject_id": "s1",
                    "type": rtype,
                    "verified": False,
                }
                if kwargs:
                    req.update(kwargs)
                out = self.process(requests=[req])
                result = out["results"][0]
                self.assertEqual(result["status"], "rejected")
                self.assertEqual(result["reason"], "identity_not_verified")
                self.assertEqual(out["records"], RECORDS)

    def test_delete_removes_all_subject_records_sorted(self):
        out = self.process(requests=[delete_req("q1", "s1")])
        result = out["results"][0]
        self.assertEqual(result["deleted_count"], 2)
        self.assertEqual(result["record_ids"], ["r1", "r2"])
        self.assertEqual(
            out["records"], [record("r3", "s2", {"name": "other"})]
        )

    def test_repeated_delete_returns_zero(self):
        out = self.process(
            requests=[delete_req("q1", "s1"), delete_req("q2", "s1"), export_req("q3", "s1")]
        )
        self.assertEqual(out["results"][0]["deleted_count"], 2)
        self.assertEqual(out["results"][0]["record_ids"], ["r1", "r2"])
        self.assertEqual(out["results"][1]["deleted_count"], 0)
        self.assertEqual(out["results"][1]["record_ids"], [])
        self.assertEqual(out["results"][2]["records"], [])

    def test_requests_apply_in_order(self):
        out = self.process(
            requests=[
                export_req("q1", "s1"),
                correct_req(
                    "q2",
                    "s1",
                    [change("r2", "/nested/b", 2), change("r2", "/arr/1", 99)],
                ),
                export_req("q3", "s1"),
            ]
        )
        self.assertEqual(
            [e["data"]["nested"]["b"] for e in out["results"][0]["records"] if e["record_id"] == "r2"][0],
            1,
        )
        r2 = next(e for e in out["results"][2]["records"] if e["record_id"] == "r2")
        self.assertEqual(r2["data"]["nested"], {"b": 2})
        self.assertEqual(r2["data"]["arr"], [10, 99])

    def test_correction_locations_sorted_by_record_id_then_path(self):
        out = self.process(
            requests=[
                correct_req(
                    "q1",
                    "s1",
                    [
                        change("r2", "/name", "n"),
                        change("r1", "/name", "f"),
                        change("r2", "/arr/0", 1),
                    ],
                )
            ]
        )
        self.assertEqual(
            out["results"][0]["changes"],
            [
                {"record_id": "r1", "path": "/name"},
                {"record_id": "r2", "path": "/arr/0"},
                {"record_id": "r2", "path": "/name"},
            ],
        )

    def test_correction_applies_to_export_and_final_records(self):
        out = self.process(
            requests=[
                correct_req("q1", "s1", [change("r1", "/name", "updated")]),
                export_req("q2", "s1"),
            ]
        )
        r1 = next(e for e in out["results"][1]["records"] if e["record_id"] == "r1")
        self.assertEqual(r1["data"], {"name": "updated"})
        final_r1 = next(r for r in out["records"] if r["record_id"] == "r1")
        self.assertEqual(final_r1["data"], {"name": "updated"})

    def test_final_records_keep_original_order_after_delete(self):
        out = self.process(requests=[delete_req("q1", "s1")])
        self.assertEqual([r["record_id"] for r in out["records"]], ["r3"])

    def test_delete_before_correct_makes_target_missing(self):
        with self.assertRaises(InvalidCorrection):
            self.process(
                requests=[
                    delete_req("q1", "s1"),
                    correct_req("q2", "s1", [change("r1", "/name", "x")]),
                ]
            )

    def test_input_is_not_mutated(self):
        payload = {
            "records": copy.deepcopy(RECORDS),
            "requests": [
                correct_req("q1", "s1", [change("r2", "/nested", {"b": 9})]),
                delete_req("q2", "s2"),
            ],
        }
        snapshot = copy.deepcopy(payload)
        process_subject_requests(payload)
        self.assertEqual(payload, snapshot)

    def test_results_share_order_with_requests(self):
        out = self.process(
            requests=[
                delete_req("q1", "s1"),
                export_req("q2", "s2"),
                correct_req("q3", "s2", [change("r3", "/name", "z")]),
            ]
        )
        self.assertEqual(
            [(r["request_id"], r["type"]) for r in out["results"]],
            [("q1", "delete"), ("q2", "export"), ("q3", "correct")],
        )


class SubjectRequestsValidationTest(unittest.TestCase):
    def assert_invalid(self, exc, payload):
        with self.assertRaises(exc):
            process_subject_requests(payload)

    def test_invalid_request_root_or_arrays(self):
        good = export_req("q1", "s1")
        for payload in (
            [],
            "x",
            {},
            {"records": []},
            {"requests": [good]},
            {"records": [], "requests": [good]},
            {"records": RECORDS},
            {"records": RECORDS, "requests": []},
            {"records": RECORDS, "requests": "x"},
            {"records": "x", "requests": [good]},
        ):
            with self.subTest(payload=payload):
                self.assert_invalid(InvalidRequest, payload)

    def test_invalid_record(self):
        good = export_req("q1", "s1")
        for records in (
            [[], ],
            [{"record_id": "r", "subject_id": "s", "data": {}}, "x"],
            [{"record_id": "", "subject_id": "s", "data": {}}],
            [{"record_id": "r", "subject_id": "", "data": {}}],
            [{"record_id": 1, "subject_id": "s", "data": {}}],
            [{"record_id": "r", "subject_id": "s"}],
            [{"record_id": "r", "subject_id": "s", "data": "not-object"}],
            [record("r", "s", {}), record("r", "s", {})],
        ):
            with self.subTest(records=records):
                self.assert_invalid(InvalidRecord, {"records": records, "requests": [good]})

    def test_invalid_subject_request(self):
        for req in (
            {},
            "x",
            {"request_id": "", "subject_id": "s1", "type": "export", "verified": True},
            {"request_id": "q", "subject_id": 5, "type": "export", "verified": True},
            {"request_id": "q", "subject_id": "s1", "type": "erase", "verified": True},
            {"request_id": "q", "subject_id": "s1", "type": "export", "verified": "yes"},
            export_req("q", "s1", changes=[]),
            delete_req("q", "s1", changes=[]),
            {
                "request_id": "q",
                "subject_id": "s1",
                "type": "correct",
                "verified": True,
            },
        ):
            with self.subTest(req=req):
                self.assert_invalid(
                    InvalidSubjectRequest, {"records": RECORDS, "requests": [req]}
                )

    def test_duplicate_request_id(self):
        self.assert_invalid(
            InvalidSubjectRequest,
            {
                "records": RECORDS,
                "requests": [export_req("q1", "s1"), export_req("q1", "s2")],
            },
        )

    def test_invalid_correction_entries(self):
        base = {"records": RECORDS}
        cases = {
            "changes_not_array": correct_req("q", "s1", "x"),
            "changes_empty": correct_req("q", "s1", []),
            "change_not_object": correct_req("q", "s1", ["x"]),
            "change_missing_value": correct_req(
                "q", "s1", [{"record_id": "r1", "path": "/name"}]
            ),
            "change_empty_record_id": correct_req("q", "s1", [change("", "/name", 1)]),
            "root_pointer": correct_req("q", "s1", [change("r1", "", 1)]),
            "bad_escape": correct_req("q", "s1", [change("r1", "/na~2me", 1)]),
            "missing_member": correct_req("q", "s1", [change("r1", "/missing", 1)]),
            "missing_record": correct_req("q", "s1", [change("zz", "/name", 1)]),
            "other_subject": correct_req("q", "s2", [change("r1", "/name", 1)]),
            "array_oob": correct_req("q", "s1", [change("r2", "/arr/9", 1)]),
            "array_dash": correct_req("q", "s1", [change("r2", "/arr/-", 1)]),
            "leading_zero": correct_req("q", "s1", [change("r2", "/arr/01", 1)]),
            "duplicate_path": correct_req(
                "q", "s1", [change("r1", "/name", 1), change("r1", "/name", 2)]
            ),
            "ancestor_paths": correct_req(
                "q",
                "s1",
                [change("r2", "/nested", 1), change("r2", "/nested/b", 2)],
            ),
        }
        for name, req in cases.items():
            with self.subTest(name=name):
                self.assert_invalid(InvalidCorrection, {**base, "requests": [req]})

    def test_overlapping_paths_on_different_records_allowed(self):
        out = process_subject_requests(
            {
                "records": RECORDS,
                "requests": [
                    correct_req(
                        "q",
                        "s1",
                        [change("r1", "/name", "a"), change("r2", "/name", "b")],
                    )
                ],
            }
        )
        self.assertEqual(len(out["results"][0]["changes"]), 2)

    def test_static_overlap_rejected_even_when_unverified(self):
        self.assert_invalid(
            InvalidCorrection,
            {
                "records": RECORDS,
                "requests": [
                    correct_req(
                        "q",
                        "s1",
                        [change("r1", "/name", 1), change("r1", "/name", 2)],
                        verified=False,
                    )
                ],
            },
        )

    def test_pointer_escapes_resolve(self):
        records = [record("r1", "s1", {"a/b": {"~x": 1}})]
        out = process_subject_requests(
            {
                "records": records,
                "requests": [
                    correct_req("q", "s1", [change("r1", "/a~1b/~0x", 42)])
                ],
            }
        )
        self.assertEqual(out["records"][0]["data"], {"a/b": {"~x": 42}})

    def test_failure_returns_no_partial_results(self):
        # A late invalid correction must not surface earlier deletions.
        with self.assertRaises(InvalidCorrection):
            process_subject_requests(
                {
                    "records": RECORDS,
                    "requests": [
                        delete_req("q1", "s1"),
                        correct_req("q2", "s2", [change("r3", "/missing", 1)]),
                    ],
                }
            )


class SubjectRequestsHttpTest(unittest.TestCase):
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
        return self.request("POST", "/v1/subject-requests/process", body=body, content_type=content_type)

    PATH = "/v1/subject-requests/process"

    def test_happy_path_http(self):
        status, payload = self.post(
            {"records": RECORDS, "requests": [export_req("q1", "s1")]}
        )
        self.assertEqual(status, 200)
        self.assertIn("results", payload)
        self.assertIn("records", payload)
        self.assertEqual(len(payload["results"][0]["records"]), 2)

    def test_unsupported_media_type(self):
        status, payload = self.post({"records": RECORDS, "requests": [export_req("q", "s1")]},
                                    content_type="text/plain")
        self.assertEqual(status, 415)
        self.assertEqual(payload["error"]["code"], "unsupported_media_type")

    def test_invalid_json(self):
        status, payload = self.post("{not json")
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"]["code"], "invalid_json")

    def test_error_codes(self):
        cases = [
            ("invalid_request", {}),
            ("invalid_record", {"records": [record("r", "s", {}), record("r", "s", {})],
                                "requests": [export_req("q", "s")]}),
            ("invalid_subject_request", {"records": RECORDS,
                                         "requests": [export_req("q", "s1", verified=1)]}),
            ("invalid_correction", {"records": RECORDS,
                                    "requests": [correct_req("q", "s1", [change("r1", "/x", 1)])]}),
        ]
        for code, payload in cases:
            with self.subTest(code=code):
                status, body = self.post(payload)
                self.assertEqual(status, 422)
                self.assertEqual(body["error"]["code"], code)

    def test_method_not_allowed(self):
        for method in ("GET", "PUT", "DELETE", "PATCH"):
            with self.subTest(method=method):
                status, payload = self.request(method, self.PATH)
                self.assertEqual(status, 405)
                self.assertEqual(payload["error"]["code"], "method_not_allowed")

    def test_unknown_path_404(self):
        status, payload = self.request("POST", "/v1/subject-requests")
        self.assertEqual(status, 404)
        self.assertEqual(payload["error"]["code"], "not_found")


class ServiceSurfaceTest(unittest.TestCase):
    def test_service_delegates(self):
        service = Service()
        out = service.process_subject_requests(
            {"records": RECORDS, "requests": [export_req("q1", "s1")]}
        )
        self.assertEqual(len(out["results"]), 1)
        self.assertEqual(len(out["records"]), 3)


if __name__ == "__main__":
    unittest.main()
