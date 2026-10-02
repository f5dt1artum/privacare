import copy
import http.client
import json
import threading
import unittest
from http.server import ThreadingHTTPServer

from privacare.classifier import InvalidRequest
from privacare.risk import InvalidK, InvalidQuasiIdentifiers
from privacare.server import Handler
from privacare.service import Service


def assess(payload):
    return Service().reidentification_risk(payload)


def body(records, pointers, k=2):
    return {"records": records, "quasi_identifiers": pointers, "k": k}


class EquivalenceClassTest(unittest.TestCase):
    def test_grouping_summary_and_results(self):
        records = [
            {"age": 30, "sex": "M", "city": "BJ"},
            {"age": 30, "sex": "M", "city": "SH"},
            {"age": 30, "sex": "F", "city": "BJ"},
            {"age": 40, "sex": "M", "city": "BJ"},
            {"age": 30, "sex": "F", "city": "BJ"},
        ]
        payload = body(records, ["/age", "/sex", "/city"], k=2)
        response = assess(payload)
        summary = response["summary"]
        self.assertEqual(
            summary,
            {
                "k": 2,
                "record_count": 5,
                "equivalence_class_count": 4,
                "minimum_class_size": 1,
                "at_risk_records": 3,
                "at_risk_rate": 0.6,
            },
        )
        results = response["results"]
        self.assertEqual([r["index"] for r in results], [0, 1, 2, 3, 4])
        self.assertEqual([r["class_size"] for r in results], [1, 1, 2, 1, 2])
        self.assertEqual([r["risk_score"] for r in results], [1.0, 1.0, 0.5, 1.0, 0.5])
        self.assertEqual([r["at_risk"] for r in results], [True, True, False, True, False])
        for result in results:
            self.assertEqual(set(result), {"index", "class_size", "risk_score", "at_risk"})
        self.assertEqual(set(response), {"summary", "results"})

    def test_k_threshold_boundary(self):
        records = [{"a": 1}, {"a": 1}, {"a": 1}, {"a": 2}, {"a": 2}]
        k2 = assess(body(records, ["/a"], k=2))
        self.assertEqual([r["at_risk"] for r in k2["results"]], [False, False, False, False, False])
        self.assertEqual(k2["summary"]["at_risk_records"], 0)
        self.assertEqual(k2["summary"]["at_risk_rate"], 0.0)
        k4 = assess(body(records, ["/a"], k=4))
        self.assertEqual([r["at_risk"] for r in k4["results"]], [True, True, True, True, True])
        self.assertEqual(k4["summary"]["minimum_class_size"], 2)

    def test_null_participates_in_grouping(self):
        records = [{"a": None}, {"a": None}, {"a": 0}, {"a": False}]
        response = assess(body(records, ["/a"]))
        self.assertEqual(response["summary"]["equivalence_class_count"], 3)
        self.assertEqual([r["class_size"] for r in response["results"]], [2, 2, 1, 1])
        # null must not be confused with 0 or false
        self.assertTrue(response["results"][2]["at_risk"])
        self.assertTrue(response["results"][3]["at_risk"])

    def test_strings_are_case_sensitive(self):
        records = [{"s": "M"}, {"s": "m"}, {"s": "M"}]
        response = assess(body(records, ["/s"]))
        self.assertEqual(response["summary"]["equivalence_class_count"], 2)
        self.assertEqual([r["class_size"] for r in response["results"]], [2, 1, 2])

    def test_boolean_not_equal_to_number(self):
        records = [{"v": True}, {"v": 1}, {"v": True}, {"v": False}, {"v": 0}]
        response = assess(body(records, ["/v"]))
        self.assertEqual(response["summary"]["equivalence_class_count"], 4)
        self.assertEqual([r["class_size"] for r in response["results"]], [2, 1, 2, 1, 1])

    def test_json_numbers_equal_by_numeric_value(self):
        records = [{"n": 1}, {"n": 1.0}, {"n": 2.0}, {"n": 2}, {"n": 1}]
        response = assess(body(records, ["/n"], k=3))
        self.assertEqual(response["summary"]["equivalence_class_count"], 2)
        self.assertEqual([r["class_size"] for r in response["results"]], [3, 3, 2, 2, 3])
        self.assertEqual(response["results"][0]["risk_score"], 0.333333)

    def test_nested_pointers_and_array_indices(self):
        records = [
            {"profile": {"age": 30}, "vitals": [72, 120]},
            {"profile": {"age": 30}, "vitals": [72, 130]},
            {"profile": {"age": 31}, "vitals": [72, 120]},
        ]
        response = assess(body(records, ["/profile/age", "/vitals/0"]))
        self.assertEqual([r["class_size"] for r in response["results"]], [2, 2, 1])

    def test_escaped_pointer_segments(self):
        records = [{"a/b": 1, "m~n": 9}, {"a/b": 1, "m~n": 8}]
        response = assess(body(records, ["/a~1b"]))
        self.assertEqual([r["class_size"] for r in response["results"]], [2, 2])
        response = assess(body(records, ["/m~0n"]))
        self.assertEqual([r["class_size"] for r in response["results"]], [1, 1])

    def test_risk_score_half_up_rounding(self):
        # class size 6: 1/6 = 0.166666... -> 0.166667
        records = [{"a": 0}] * 6 + [{"a": 1}, {"a": 2}]
        response = assess(body(records, ["/a"], k=100))
        six_group = next(r for r in response["results"] if r["class_size"] == 6)
        self.assertEqual(six_group["risk_score"], 0.166667)
        singleton = next(r for r in response["results"] if r["class_size"] == 1)
        self.assertEqual(singleton["risk_score"], 1.0)

    def test_half_up_tie_at_seventh_decimal(self):
        # 1/128 = 0.0078125: half up -> 0.007813, banker's rounding -> 0.007812
        records = [{"a": 0}] * 128
        response = assess(body(records, ["/a"], k=129))
        self.assertEqual(response["results"][0]["risk_score"], 0.007813)
        self.assertEqual(response["summary"]["at_risk_rate"], 1.0)

    def test_rate_half_up_tie(self):
        # exactly one at-risk record out of 128 -> 1/128 = 0.0078125 -> 0.007813
        records = [{"a": 0}] + [{"a": 1}] * 127
        response = assess(body(records, ["/a"], k=2))
        self.assertEqual(response["summary"]["at_risk_records"], 1)
        self.assertEqual(response["summary"]["at_risk_rate"], 0.007813)

    def test_order_does_not_change_per_record_outcomes(self):
        records = [
            {"age": 30, "sex": "M"},
            {"age": 30, "sex": "M"},
            {"age": 30, "sex": "F"},
            {"age": 40, "sex": "M"},
        ]
        pointers = ["/age", "/sex"]
        first = assess(body(records, pointers))
        reordered = [records[2], records[0], records[3], records[1]]
        second = assess(body(reordered, pointers))
        # 组大小与风险结论只取决于记录本身
        by_signature = [
            (r["class_size"], r["risk_score"], r["at_risk"]) for r in first["results"]
        ]
        reordered_signatures = [
            (r["class_size"], r["risk_score"], r["at_risk"]) for r in second["results"]
        ]
        self.assertEqual(
            [by_signature[i] for i in (2, 0, 3, 1)], reordered_signatures
        )
        self.assertEqual(first["summary"], second["summary"])

    def test_deterministic_and_input_not_mutated(self):
        payload = body([{"a": 1}, {"a": 1}, {"a": 2}], ["/a"])
        snapshot = copy.deepcopy(payload)
        first = assess(payload)
        second = assess(payload)
        self.assertEqual(first, second)
        self.assertEqual(payload, snapshot)

    def test_response_does_not_echo_quasi_values(self):
        secret = "rare-disease-value"
        payload = body([{"dx": secret}, {"dx": "other"}], ["/dx"])
        blob = json.dumps(assess(payload), ensure_ascii=False)
        self.assertNotIn(secret, blob)
        self.assertNotIn("other", blob)


class QuasiIdentifierValidationTest(unittest.TestCase):
    def test_not_a_compliant_array(self):
        base_records = [{"a": 1}]
        for raw in (None, [], "x", [1], ["/a", 2], ["/a", None]):
            with self.subTest(raw=raw):
                with self.assertRaises(InvalidQuasiIdentifiers):
                    assess({"records": base_records, "quasi_identifiers": raw, "k": 2})

    def test_missing_quasi_identifiers_is_invalid_quasi_identifiers(self):
        with self.assertRaises(InvalidQuasiIdentifiers):
            assess({"records": [{"a": 1}], "k": 2})

    def test_duplicates_rejected(self):
        with self.assertRaises(InvalidQuasiIdentifiers):
            assess({"records": [{"a": 1}], "quasi_identifiers": ["/a", "/a"], "k": 2})

    def test_invalid_pointer_syntax(self):
        for pointer in ("a", "/a~2", "/a~"):
            with self.subTest(pointer=pointer):
                with self.assertRaises(InvalidQuasiIdentifiers):
                    assess(body([{"a": 1}], [pointer]))

    def test_pointer_missing_out_of_bounds_or_container(self):
        cases = [
            ([{"a": 1}], ["/b"]),                        # missing key
            ([{"a": 1}], ["/a/x"]),                     # descent into scalar
            ([{"xs": [1]}], ["/xs/2"]),                 # array out of bounds
            ([{"xs": [1]}], ["/xs/-"]),                 # RFC index, never resolves
            ([{"xs": [1]}], ["/xs/01"]),                # leading zero
            ([{"a": {"b": 1}}], ["/a"]),                # object container
            ([{"a": [1]}], ["/a"]),                     # array container
            ([{"a": 1}, {"b": 1}], ["/a"]),             # missing on one record
        ]
        for records, pointers in cases:
            with self.subTest(pointers=pointers):
                with self.assertRaises(InvalidQuasiIdentifiers):
                    assess(body(records, pointers))

    def test_empty_key_pointer_is_valid(self):
        response = assess(body([{"": 5}, {"": 5}], ["/"]))
        self.assertEqual(response["summary"]["equivalence_class_count"], 1)


class KValidationTest(unittest.TestCase):
    def test_invalid_k(self):
        for k_value in (True, False, 1, 0, -2, 1.5, 2.0, "2", None, [2]):
            with self.subTest(k=k_value):
                with self.assertRaises(InvalidK):
                    assess({"records": [{"a": 1}], "quasi_identifiers": ["/a"], "k": k_value})

    def test_missing_k_is_invalid_request_shape_but_invalid_k_code(self):
        with self.assertRaises(InvalidK):
            assess({"records": [{"a": 1}], "quasi_identifiers": ["/a"]})


class RequestShapeValidationTest(unittest.TestCase):
    def test_invalid_request(self):
        good_pointers = ["/a"]
        for payload in (
            None,
            [],
            "x",
            {},
            {"records": None, "quasi_identifiers": good_pointers, "k": 2},
            {"records": [], "quasi_identifiers": good_pointers, "k": 2},
            {"records": [1], "quasi_identifiers": good_pointers, "k": 2},
            {"records": ["s"], "quasi_identifiers": good_pointers, "k": 2},
        ):
            with self.subTest(payload=payload):
                with self.assertRaises(InvalidRequest):
                    assess(payload)

    def test_records_validated_before_pointer_resolution(self):
        with self.assertRaises(InvalidRequest):
            assess({"records": [1], "quasi_identifiers": ["/missing"], "k": 2})


class RiskHttpTest(unittest.TestCase):
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
        raw = payload if isinstance(payload, (str, bytes)) else json.dumps(payload)
        return self.request("POST", "/v1/reidentification-risk", body=raw, content_type=content_type)

    def test_happy_path(self):
        status, payload, _ = self.post(
            {
                "records": [
                    {"age": 30, "sex": "M"},
                    {"age": 30, "sex": "M"},
                    {"age": 31, "sex": "F"},
                ],
                "quasi_identifiers": ["/age", "/sex"],
                "k": 2,
            }
        )
        self.assertEqual(status, 200)
        self.assertEqual(set(payload), {"summary", "results"})
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
        self.assertEqual([r["index"] for r in payload["results"]], [0, 1, 2])
        self.assertEqual([r["class_size"] for r in payload["results"]], [2, 2, 1])
        blob = json.dumps(payload, ensure_ascii=False)
        self.assertNotIn("30", blob)
        self.assertNotIn("31", blob)

    def test_method_not_allowed(self):
        for method in ("GET", "PUT", "DELETE", "PATCH"):
            with self.subTest(method=method):
                status, payload, allow = self.request(method, "/v1/reidentification-risk")
                self.assertEqual(status, 405)
                self.assertEqual(payload["error"]["code"], "method_not_allowed")
                self.assertEqual(allow, "POST")

    def test_unknown_path_still_404(self):
        for method, path in (("POST", "/v1/nope"), ("GET", "/nope")):
            with self.subTest(method=method, path=path):
                status, payload, _ = self.request(method, path)
                self.assertEqual(status, 404)
                self.assertEqual(payload["error"]["code"], "not_found")

    def test_unsupported_media_type(self):
        status, payload, _ = self.post({"records": [{}]}, content_type="text/plain")
        self.assertEqual(status, 415)
        self.assertEqual(payload["error"]["code"], "unsupported_media_type")

    def test_invalid_json(self):
        status, payload, _ = self.post("{not json")
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"]["code"], "invalid_json")

    def test_invalid_request(self):
        for raw in ("[]", "{}", '{"records": []}', '{"records": [1]}'):
            with self.subTest(raw=raw):
                status, payload, _ = self.post(raw)
                self.assertEqual(status, 422)
                self.assertEqual(payload["error"]["code"], "invalid_request")

    def test_invalid_quasi_identifiers(self):
        cases = [
            {"records": [{"a": 1}], "quasi_identifiers": [], "k": 2},
            {"records": [{"a": 1}], "quasi_identifiers": ["/b"], "k": 2},
            {"records": [{"a": {"b": 1}}], "quasi_identifiers": ["/a"], "k": 2},
            {"records": [{"a": 1}], "quasi_identifiers": ["a"], "k": 2},
            {"records": [{"a": 1}], "quasi_identifiers": ["/a", "/a"], "k": 2},
        ]
        for payload in cases:
            with self.subTest(payload=payload):
                status, parsed, _ = self.post(payload)
                self.assertEqual(status, 422)
                self.assertEqual(parsed["error"]["code"], "invalid_quasi_identifiers")

    def test_invalid_k(self):
        for k_value in ("true", "1", "1.5", '"2"'):
            with self.subTest(k=k_value):
                status, payload, _ = self.post(
                    '{"records": [{"a": 1}], "quasi_identifiers": ["/a"], "k": %s}' % k_value
                )
                self.assertEqual(status, 422)
                self.assertEqual(payload["error"]["code"], "invalid_k")

    def test_no_partial_results_on_failure(self):
        status, payload, _ = self.post(
            {"records": [{"a": 1}, {"b": 2}], "quasi_identifiers": ["/a"], "k": 2}
        )
        self.assertEqual(status, 422)
        self.assertNotIn("results", payload)
        self.assertNotIn("summary", payload)

    def test_existing_endpoints_keep_results_envelope(self):
        status, payload, _ = self.request(
            "POST", "/v1/classify", body=json.dumps({"records": [{"note": "x"}]}),
            content_type="application/json",
        )
        self.assertEqual(status, 200)
        self.assertIn("results", payload)
        self.assertNotIn("summary", payload)


if __name__ == "__main__":
    unittest.main()
