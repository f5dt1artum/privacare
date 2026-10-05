import copy
import http.client
import json
import threading
import unittest
from http.server import ThreadingHTTPServer

from privacare.classifier import InvalidRequest, InvalidSchema
from privacare.server import Handler
from privacare.service import Service
from privacare.synthetic import InvalidRealRecords, InvalidSyntheticRecords


def evaluate(payload):
    return Service().evaluate_synthetic(payload)


def body(real, synthetic, fields):
    return {"real_records": real, "synthetic_records": synthetic, "fields": fields}


REAL = [
    {"age": 30, "sex": "M"},
    {"age": 40, "sex": "F"},
    {"age": 30, "sex": "M"},
    {"age": 50, "sex": "F"},
]
SYNTHETIC = [
    {"age": 30, "sex": "M"},
    {"age": 60, "sex": "M"},
]
FIELDS = [
    {"path": "/sex", "kind": "categorical"},
    {"path": "/age", "kind": "numeric"},
]


class HappyPathTest(unittest.TestCase):
    def test_counts_fields_and_utilities(self):
        response = evaluate(body(REAL, SYNTHETIC, FIELDS))
        self.assertEqual(response["real_count"], 4)
        self.assertEqual(response["synthetic_count"], 2)
        # fields sorted by path: /age before /sex
        self.assertEqual([f["path"] for f in response["fields"]], ["/age", "/sex"])
        by_path = {f["path"]: f for f in response["fields"]}
        self.assertEqual(by_path["/age"]["kind"], "numeric")
        self.assertEqual(by_path["/age"]["distance"], 0.5)
        self.assertEqual(by_path["/age"]["utility"], 0.5)
        self.assertEqual(by_path["/sex"]["kind"], "categorical")
        self.assertEqual(by_path["/sex"]["distance"], 0.5)
        self.assertEqual(by_path["/sex"]["utility"], 0.5)
        self.assertEqual(response["overall_utility"], 0.5)
        self.assertEqual(response["exact_match_count"], 1)
        self.assertEqual(response["exact_match_rate"], 0.5)
        self.assertEqual(
            set(response),
            {
                "real_count",
                "synthetic_count",
                "fields",
                "overall_utility",
                "exact_match_count",
                "exact_match_rate",
            },
        )
        for field in response["fields"]:
            self.assertEqual(set(field), {"path", "kind", "distance", "utility"})

    def test_identical_distributions_give_perfect_utility(self):
        records = [{"a": 1, "b": "x"}, {"a": 2, "b": "y"}]
        response = evaluate(
            body(records, records, [{"path": "/a", "kind": "numeric"}, {"path": "/b", "kind": "categorical"}])
        )
        self.assertEqual(response["overall_utility"], 1.0)
        self.assertEqual(response["exact_match_count"], 2)
        self.assertEqual(response["exact_match_rate"], 1.0)

    def test_disjoint_categorical_values_give_zero_utility(self):
        response = evaluate(
            body([{"c": None}], [{"c": "x"}], [{"path": "/c", "kind": "categorical"}])
        )
        self.assertEqual(response["fields"][0]["distance"], 1.0)
        self.assertEqual(response["fields"][0]["utility"], 0.0)
        self.assertEqual(response["overall_utility"], 0.0)

    def test_categorical_tvd_over_union(self):
        real = [{"c": "a"}, {"c": "a"}, {"c": "b"}, {"c": "c"}]
        synthetic = [{"c": "a"}, {"c": "b"}, {"c": "b"}, {"c": "d"}]
        response = evaluate(body(real, synthetic, [{"path": "/c", "kind": "categorical"}]))
        # |0.5-0.25| + |0.25-0.5| + |0.25-0| + |0-0.25| = 1.0 -> TVD 0.5
        self.assertEqual(response["fields"][0]["distance"], 0.5)

    def test_numeric_ks_distance(self):
        real = [{"n": 1}, {"n": 2}, {"n": 3}, {"n": 4}]
        synthetic = [{"n": 3}, {"n": 4}, {"n": 5}, {"n": 6}]
        response = evaluate(body(real, synthetic, [{"path": "/n", "kind": "numeric"}]))
        # largest CDF gap is at 2: 0.5 vs 0.0
        self.assertEqual(response["fields"][0]["distance"], 0.5)
        self.assertEqual(response["fields"][0]["utility"], 0.5)

    def test_six_decimal_rounding(self):
        real = [{"c": "a"}, {"c": "a"}, {"c": "b"}]
        synthetic = [{"c": "a"}, {"c": "b"}, {"c": "b"}]
        response = evaluate(body(real, synthetic, [{"path": "/c", "kind": "categorical"}]))
        # TVD = |2/3 - 1/3| / 2 * 2 sides = 1/3
        self.assertEqual(response["fields"][0]["distance"], 0.333333)
        self.assertEqual(response["fields"][0]["utility"], 0.666667)

    def test_exact_match_json_type_boundaries(self):
        # 1 and 1.0 are the same JSON number.
        response = evaluate(
            body([{"n": 1}], [{"n": 1.0}], [{"path": "/n", "kind": "numeric"}])
        )
        self.assertEqual(response["exact_match_count"], 1)
        # true and 1 are different JSON values; null and false differ too.
        response = evaluate(
            body(
                [{"b": True}, {"b": None}],
                [{"b": False}, {"b": None}],
                [{"path": "/b", "kind": "categorical"}],
            )
        )
        self.assertEqual(response["exact_match_count"], 1)
        self.assertEqual(response["exact_match_rate"], 0.5)

    def test_exact_match_counts_each_synthetic_record_once(self):
        real = [{"n": 1}]
        synthetic = [{"n": 1}, {"n": 1}, {"n": 2}]
        response = evaluate(body(real, synthetic, [{"path": "/n", "kind": "numeric"}]))
        self.assertEqual(response["exact_match_count"], 2)
        self.assertEqual(response["exact_match_rate"], 0.666667)

    def test_nested_and_array_paths(self):
        real = [{"vitals": {"hr": [70, 72]}}]
        synthetic = [{"vitals": {"hr": [70, 90]}}]
        fields = [{"path": "/vitals/hr/1", "kind": "numeric"}]
        response = evaluate(body(real, synthetic, fields))
        self.assertEqual(response["real_count"], 1)
        self.assertEqual(response["exact_match_count"], 0)
        # CDFs: real point mass at 72, synthetic at 90 -> KS distance 1
        self.assertEqual(response["fields"][0]["distance"], 1.0)

    def test_no_input_echo_and_no_mutation(self):
        real = [{"name": "张三", "age": 30}]
        synthetic = [{"name": "李四", "age": 31}]
        payload = body(
            real,
            synthetic,
            [{"path": "/age", "kind": "numeric"}, {"path": "/name", "kind": "categorical"}],
        )
        snapshot = copy.deepcopy(payload)
        response = evaluate(payload)
        self.assertEqual(payload, snapshot)
        text = json.dumps(response, ensure_ascii=False)
        self.assertNotIn("张三", text)
        self.assertNotIn("李四", text)
        self.assertNotIn("30", text.split('"fields"')[0])

    def test_deterministic_across_calls(self):
        payload = body(REAL, SYNTHETIC, FIELDS)
        self.assertEqual(evaluate(copy.deepcopy(payload)), evaluate(copy.deepcopy(payload)))


class InvalidRequestTest(unittest.TestCase):
    def assert_invalid_request(self, payload):
        with self.assertRaises(InvalidRequest):
            evaluate(payload)

    def test_root_must_be_object(self):
        self.assert_invalid_request([1, 2])
        self.assert_invalid_request("nope")

    def test_arrays_missing_wrong_type_or_empty(self):
        self.assert_invalid_request({})
        self.assert_invalid_request(body([], SYNTHETIC, FIELDS))
        self.assert_invalid_request(body(REAL, [], FIELDS))
        self.assert_invalid_request(body(REAL, SYNTHETIC, []))
        self.assert_invalid_request(body("x", SYNTHETIC, FIELDS))
        self.assert_invalid_request(body(REAL, None, FIELDS))
        self.assert_invalid_request(body(REAL, SYNTHETIC, {"path": "/a"}))
        self.assert_invalid_request({"synthetic_records": SYNTHETIC, "fields": FIELDS})


class InvalidSchemaTest(unittest.TestCase):
    def assert_invalid_schema(self, fields):
        with self.assertRaises(InvalidSchema):
            evaluate(body(REAL, SYNTHETIC, fields))

    def test_field_must_be_object_with_path_and_kind(self):
        self.assert_invalid_schema(["/a"])
        self.assert_invalid_schema([{"kind": "numeric"}])
        self.assert_invalid_schema([{"path": "/a"}])
        self.assert_invalid_schema([{"path": 1, "kind": "numeric"}])

    def test_path_must_be_non_root_pointer(self):
        self.assert_invalid_schema([{"path": "", "kind": "numeric"}])
        self.assert_invalid_schema([{"path": "a", "kind": "numeric"}])
        self.assert_invalid_schema([{"path": "/a~2b", "kind": "numeric"}])

    def test_paths_must_be_unique(self):
        self.assert_invalid_schema(
            [{"path": "/age", "kind": "numeric"}, {"path": "/age", "kind": "categorical"}]
        )

    def test_kind_must_be_categorical_or_numeric(self):
        self.assert_invalid_schema([{"path": "/age", "kind": "text"}])
        self.assert_invalid_schema([{"path": "/age", "kind": 1}])


class InvalidRecordsTest(unittest.TestCase):
    def test_real_record_must_be_object(self):
        with self.assertRaises(InvalidRealRecords):
            evaluate(body([1], SYNTHETIC, FIELDS))

    def test_synthetic_record_must_be_object(self):
        with self.assertRaises(InvalidSyntheticRecords):
            evaluate(body(REAL, ["nope"], FIELDS))

    def test_unresolvable_path(self):
        with self.assertRaises(InvalidRealRecords):
            evaluate(body([{"age": 30}], SYNTHETIC, FIELDS))
        with self.assertRaises(InvalidSyntheticRecords):
            evaluate(body(REAL, [{"age": 30, "sex": "M"}, {"age": 30}], FIELDS))

    def test_container_target_rejected(self):
        with self.assertRaises(InvalidRealRecords):
            evaluate(
                body([{"a": {"b": 1}}], [{"a": {"b": 1}}], [{"path": "/a", "kind": "numeric"}])
            )
        with self.assertRaises(InvalidSyntheticRecords):
            evaluate(
                body([{"a": "x"}], [{"a": ["x"]}], [{"path": "/a", "kind": "categorical"}])
            )

    def test_kind_type_mismatch(self):
        with self.assertRaises(InvalidRealRecords):
            evaluate(body([{"c": 1}], [{"c": "x"}], [{"path": "/c", "kind": "categorical"}]))
        with self.assertRaises(InvalidSyntheticRecords):
            evaluate(body([{"n": 1}], [{"n": True}], [{"path": "/n", "kind": "numeric"}]))
        with self.assertRaises(InvalidSyntheticRecords):
            evaluate(body([{"n": 1}], [{"n": "1"}], [{"path": "/n", "kind": "numeric"}]))

    def test_numeric_must_be_finite(self):
        with self.assertRaises(InvalidRealRecords):
            evaluate(
                body([{"n": float("nan")}], [{"n": 1}], [{"path": "/n", "kind": "numeric"}])
            )
        with self.assertRaises(InvalidSyntheticRecords):
            evaluate(
                body([{"n": 1}], [{"n": float("inf")}], [{"path": "/n", "kind": "numeric"}])
            )


class HttpTest(unittest.TestCase):
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

    def request(self, method, path, payload=None, content_type="application/json"):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        body = payload if isinstance(payload, (str, bytes)) else json.dumps(payload)
        conn.request(method, path, body=body, headers={"Content-Type": content_type})
        resp = conn.getresponse()
        raw = resp.read()
        headers = dict(resp.getheaders())
        conn.close()
        return resp.status, json.loads(raw), headers

    def post(self, payload, content_type="application/json"):
        status, body, _headers = self.request(
            "POST", "/v1/synthetic/evaluate", payload, content_type
        )
        return status, body

    def test_happy_path(self):
        status, payload = self.post(body(REAL, SYNTHETIC, FIELDS))
        self.assertEqual(status, 200)
        self.assertEqual(payload["real_count"], 4)
        self.assertEqual(payload["synthetic_count"], 2)
        self.assertEqual(payload["overall_utility"], 0.5)
        self.assertNotIn("results", payload)

    def test_error_codes(self):
        cases = [
            ({"real_records": []}, "invalid_request"),
            (body(REAL, SYNTHETIC, [{"path": "", "kind": "numeric"}]), "invalid_schema"),
            (body([{"age": 30}], SYNTHETIC, FIELDS), "invalid_real_records"),
            (body(REAL, [{"age": 30}], FIELDS), "invalid_synthetic_records"),
        ]
        for payload, code in cases:
            status, result = self.post(payload)
            self.assertEqual(status, 422, payload)
            self.assertEqual(result["error"]["code"], code)
            self.assertNotIn("fields", result)

    def test_unsupported_media_type(self):
        status, payload = self.post(body(REAL, SYNTHETIC, FIELDS), content_type="text/plain")
        self.assertEqual(status, 415)
        self.assertEqual(payload["error"]["code"], "unsupported_media_type")

    def test_invalid_json(self):
        status, payload = self.post("{not json")
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"]["code"], "invalid_json")

    def test_method_not_allowed(self):
        status, payload, headers = self.request("GET", "/v1/synthetic/evaluate")
        self.assertEqual(status, 405)
        self.assertEqual(payload["error"]["code"], "method_not_allowed")
        self.assertEqual(headers.get("Allow"), "POST")

    def test_healthz_still_ok(self):
        status, payload, _headers = self.request("GET", "/healthz")
        self.assertEqual(status, 200)
        self.assertEqual(payload["status"], "ok")


if __name__ == "__main__":
    unittest.main()
