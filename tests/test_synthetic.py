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


def field(path, kind):
    return {"path": path, "kind": kind}


def body(real, synthetic, fields):
    return {"real_records": real, "synthetic_records": synthetic, "fields": fields}


class CategoricalDistanceTest(unittest.TestCase):
    def test_identical_distributions(self):
        records = [{"c": "a"}, {"c": "b"}, {"c": "a"}]
        response = evaluate(body(records, records, [field("/c", "categorical")]))
        result = response["fields"][0]
        self.assertEqual(result["distance"], 0.0)
        self.assertEqual(result["utility"], 1.0)
        self.assertEqual(response["overall_utility"], 1.0)
        self.assertEqual(response["exact_match_count"], 3)
        self.assertEqual(response["exact_match_rate"], 1.0)

    def test_disjoint_distributions(self):
        real = [{"c": "a"}, {"c": "a"}]
        synthetic = [{"c": "b"}, {"c": "b"}]
        response = evaluate(body(real, synthetic, [field("/c", "categorical")]))
        result = response["fields"][0]
        self.assertEqual(result["distance"], 1.0)
        self.assertEqual(result["utility"], 0.0)
        self.assertEqual(response["exact_match_count"], 0)
        self.assertEqual(response["exact_match_rate"], 0.0)

    def test_total_variation_over_union(self):
        # real: a=2/4, b=1/4, c=1/4 ; synthetic: a=1/2, b=1/2
        real = [{"c": "a"}, {"c": "a"}, {"c": "b"}, {"c": "c"}]
        synthetic = [{"c": "a"}, {"c": "b"}]
        response = evaluate(body(real, synthetic, [field("/c", "categorical")]))
        result = response["fields"][0]
        # |.5-.5| + |.25-.5| + |.25-0| = .5, TVD = .25
        self.assertEqual(result["distance"], 0.25)
        self.assertEqual(result["utility"], 0.75)

    def test_null_and_boolean_are_categorical(self):
        real = [{"c": None}, {"c": True}, {"c": "x"}]
        synthetic = [{"c": None}, {"c": False}, {"c": "x"}]
        response = evaluate(body(real, synthetic, [field("/c", "categorical")]))
        # union: null(1/3 vs 1/3), true(1/3 vs 0), false(0 vs 1/3), x(equal)
        # differences 1/3 + 1/3 = 2/3, TVD = 1/3
        self.assertEqual(response["fields"][0]["distance"], 0.333333)
        self.assertEqual(response["fields"][0]["utility"], 0.666667)
        # tuple differs only at /c for the true/false rows; null and x match
        self.assertEqual(response["exact_match_count"], 2)

    def test_strings_are_case_sensitive(self):
        real = [{"c": "M"}, {"c": "M"}]
        synthetic = [{"c": "m"}, {"c": "M"}]
        response = evaluate(body(real, synthetic, [field("/c", "categorical")]))
        # M: 1 vs .5 -> .5 ; m: 0 vs .5 -> .5 ; TVD .5
        self.assertEqual(response["fields"][0]["distance"], 0.5)


class NumericDistanceTest(unittest.TestCase):
    def test_identical_distributions(self):
        records = [{"n": 1.0}, {"n": 2.0}, {"n": 3.0}]
        response = evaluate(body(records, records, [field("/n", "numeric")]))
        self.assertEqual(response["fields"][0]["distance"], 0.0)
        self.assertEqual(response["fields"][0]["utility"], 1.0)

    def test_disjoint_distributions(self):
        real = [{"n": 1}, {"n": 2}]
        synthetic = [{"n": 3}, {"n": 4}]
        response = evaluate(body(real, synthetic, [field("/n", "numeric")]))
        self.assertEqual(response["fields"][0]["distance"], 1.0)
        self.assertEqual(response["fields"][0]["utility"], 0.0)

    def test_kolmogorov_smirnov_gap(self):
        # real CDF reaches 1 at 2; synthetic only reaches .5 there -> D=.5
        real = [{"n": 1}, {"n": 2}]
        synthetic = [{"n": 1}, {"n": 3}]
        response = evaluate(body(real, synthetic, [field("/n", "numeric")]))
        self.assertEqual(response["fields"][0]["distance"], 0.5)

    def test_ints_and_floats_compare_numerically(self):
        real = [{"n": 1}, {"n": 2}, {"n": 3}]
        synthetic = [{"n": 1.0}, {"n": 2.0}, {"n": 3.0}]
        response = evaluate(body(real, synthetic, [field("/n", "numeric")]))
        self.assertEqual(response["fields"][0]["distance"], 0.0)
        self.assertEqual(response["exact_match_count"], 3)
        self.assertEqual(response["exact_match_rate"], 1.0)

    def test_boolean_is_not_a_number(self):
        for bad in (True, False):
            with self.subTest(bad=bad):
                with self.assertRaises(InvalidRealRecords):
                    evaluate(
                        body(
                            [{"n": bad}, {"n": 1}],
                            [{"n": 1}, {"n": 2}],
                            [field("/n", "numeric")],
                        )
                    )

    def test_negative_and_fractional_values(self):
        real = [{"n": -1.5}, {"n": 0}, {"n": 2.25}]
        synthetic = [{"n": -1.5}, {"n": 0}, {"n": 2.25}]
        response = evaluate(body(real, synthetic, [field("/n", "numeric")]))
        self.assertEqual(response["fields"][0]["distance"], 0.0)


class ExactMatchTest(unittest.TestCase):
    def test_tuple_match_over_all_declared_paths(self):
        real = [{"a": "x", "n": 1}, {"a": "y", "n": 2}]
        synthetic = [{"a": "x", "n": 1}, {"a": "x", "n": 2}, {"a": "q", "n": 9}]
        response = evaluate(body(real, synthetic, [field("/a", "categorical"), field("/n", "numeric")]))
        self.assertEqual(response["exact_match_count"], 1)
        self.assertEqual(response["exact_match_rate"], round(1 / 3, 6))

    def test_each_synthetic_record_counted_once(self):
        real = [{"a": "x"}]
        synthetic = [{"a": "x"}, {"a": "x"}, {"a": "x"}]
        response = evaluate(body(real, synthetic, [field("/a", "categorical")]))
        self.assertEqual(response["exact_match_count"], 3)
        self.assertEqual(response["exact_match_rate"], 1.0)

    def test_rate_denominator_is_synthetic_count(self):
        real = [{"a": "x"}, {"a": "y"}, {"a": "z"}, {"a": "w"}]
        synthetic = [{"a": "x"}]
        response = evaluate(body(real, synthetic, [field("/a", "categorical")]))
        self.assertEqual(response["exact_match_count"], 1)
        self.assertEqual(response["exact_match_rate"], 1.0)

    def test_true_not_equal_to_one(self):
        # A single declared field can never legally hold both (categorical
        # rejects numbers, numeric rejects booleans); the JSON type boundary
        # is still enforced by the exact-match key function.
        from privacare.synthetic import _value_key

        self.assertNotEqual(_value_key(True), _value_key(1))
        self.assertEqual(_value_key(1), _value_key(1.0))
        self.assertNotEqual(_value_key(None), _value_key(False))
        with self.assertRaises(InvalidRealRecords):
            evaluate(body([{"v": 1}], [{"v": True}], [field("/v", "categorical")]))
        with self.assertRaises(InvalidRealRecords):
            evaluate(body([{"v": True}], [{"v": 1}], [field("/v", "numeric")]))

    def test_one_equal_to_one_point_zero(self):
        real = [{"v": 1}]
        synthetic = [{"v": 1.0}]
        response = evaluate(body(real, synthetic, [field("/v", "numeric")]))
        self.assertEqual(response["exact_match_count"], 1)

    def test_null_distinct_from_false(self):
        real = [{"v": None}]
        synthetic = [{"v": False}]
        response = evaluate(body(real, synthetic, [field("/v", "categorical")]))
        self.assertEqual(response["exact_match_count"], 0)

    def test_undeclared_fields_ignored(self):
        real = [{"a": "x", "extra": 1}]
        synthetic = [{"a": "x", "extra": 2}]
        response = evaluate(body(real, synthetic, [field("/a", "categorical")]))
        self.assertEqual(response["exact_match_count"], 1)


class ResponseShapeTest(unittest.TestCase):
    def test_counts_fields_sorted_and_overall_mean(self):
        real = [{"a": "x", "n": 1}, {"a": "y", "n": 2}]
        synthetic = [{"a": "x", "n": 9}]
        response = evaluate(
            body(
                real,
                synthetic,
                [field("/n", "numeric"), field("/a", "categorical")],
            )
        )
        self.assertEqual(response["real_count"], 2)
        self.assertEqual(response["synthetic_count"], 1)
        self.assertEqual([f["path"] for f in response["fields"]], ["/a", "/n"])
        for entry in response["fields"]:
            self.assertEqual(set(entry), {"path", "kind", "distance", "utility"})
        # /a categorical TVD=.5 (utility .5); /n disjoint KS=1 (utility 0)
        self.assertEqual(response["overall_utility"], 0.25)
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

    def test_half_up_rounding(self):
        # KS gap of 1/128 = 0.0078125 at the join point: real has 127 copies
        # of 1 and one 2, synthetic is all 1. Half up gives 0.007813 while
        # banker's rounding would give 0.007812.
        real = [{"n": 1}] * 127 + [{"n": 2}]
        synthetic = [{"n": 1}] * 128
        response = evaluate(body(real, synthetic, [field("/n", "numeric")]))
        self.assertEqual(response["fields"][0]["distance"], 0.007813)
        self.assertEqual(response["fields"][0]["utility"], 0.992188)

    def test_half_up_rounds_five_up(self):
        # rate 1/128 = 0.0078125 -> half up 0.007813 (banker's would .007812)
        response = evaluate(
            body(
                [{"c": "a"}] * 128,
                [{"c": "a"}] + [{"c": "b"}] * 127,
                [field("/c", "categorical")],
            )
        )
        self.assertEqual(response["exact_match_count"], 1)
        self.assertEqual(response["exact_match_rate"], 0.007813)

    def test_deterministic_and_input_not_mutated(self):
        payload = body(
            [{"a": "x", "n": 1}, {"a": "y", "n": 2}],
            [{"a": "x", "n": 1}],
            [field("/a", "categorical"), field("/n", "numeric")],
        )
        snapshot = copy.deepcopy(payload)
        first = evaluate(payload)
        second = evaluate(payload)
        self.assertEqual(first, second)
        self.assertEqual(payload, snapshot)

    def test_response_does_not_echo_input_values(self):
        secret = "rare-disease-value"
        payload = body(
            [{"dx": secret}, {"dx": "other"}],
            [{"dx": "other"}],
            [field("/dx", "categorical")],
        )
        blob = json.dumps(evaluate(payload), ensure_ascii=False)
        self.assertNotIn(secret, blob)
        self.assertNotIn("other", blob)


class SchemaValidationTest(unittest.TestCase):
    def good_records(self):
        return [{"a": "x"}], [{"a": "x"}]

    def test_field_missing_path_or_kind(self):
        real, synthetic = self.good_records()
        for fields in ([{"kind": "categorical"}], [{"path": "/a"}], [{}]):
            with self.subTest(fields=fields):
                with self.assertRaises(InvalidSchema):
                    evaluate(body(real, synthetic, fields))

    def test_field_not_object(self):
        real, synthetic = self.good_records()
        with self.assertRaises(InvalidSchema):
            evaluate(body(real, synthetic, ["/a"]))

    def test_invalid_or_root_path(self):
        # Root pointer is the empty string; "a" lacks the leading slash and
        # the others carry bad "~" escapes.
        for raw_path in ("a", "/a~2", "/a~", ""):
            with self.subTest(path=raw_path):
                with self.assertRaises(InvalidSchema):
                    evaluate(
                        body(
                            [{"a": "x"}],
                            [{"a": "x"}],
                            [field(raw_path, "categorical")],
                        )
                    )

    def test_empty_key_pointer_is_not_root(self):
        response = evaluate(
            body([{"": "x"}], [{"": "x"}], [field("/", "categorical")])
        )
        self.assertEqual(response["fields"][0]["path"], "/")
        self.assertEqual(response["overall_utility"], 1.0)

    def test_duplicate_path(self):
        real, synthetic = [{"a": 1}], [{"a": 1}]
        with self.assertRaises(InvalidSchema):
            evaluate(
                body(
                    real,
                    synthetic,
                    [field("/a", "numeric"), field("/a", "numeric")],
                )
            )

    def test_invalid_kind(self):
        real, synthetic = self.good_records()
        for kind in ("nominal", None, 1, True, ""):
            with self.subTest(kind=kind):
                with self.assertRaises(InvalidSchema):
                    evaluate(body(real, synthetic, [field("/a", kind)]))

    def test_non_string_path(self):
        real, synthetic = self.good_records()
        with self.assertRaises(InvalidSchema):
            evaluate(body(real, synthetic, [{"path": 1, "kind": "numeric"}]))


class RecordsValidationTest(unittest.TestCase):
    def test_real_record_not_object(self):
        for record in (1, "s", None, True, []):
            with self.subTest(record=record):
                with self.assertRaises(InvalidRealRecords):
                    evaluate(
                        body([record], [{"a": 1}], [field("/a", "numeric")])
                    )

    def test_synthetic_record_not_object(self):
        for record in (1, "s", None, True, []):
            with self.subTest(record=record):
                with self.assertRaises(InvalidSyntheticRecords):
                    evaluate(
                        body([{"a": 1}], [record], [field("/a", "numeric")])
                    )

    def test_unresolvable_path(self):
        fields = [field("/b", "numeric")]
        with self.assertRaises(InvalidRealRecords):
            evaluate(body([{"a": 1}], [{"b": 1}], fields))
        with self.assertRaises(InvalidSyntheticRecords):
            evaluate(body([{"b": 1}], [{"a": 1}], fields))

    def test_path_resolves_on_every_record(self):
        fields = [field("/a", "numeric")]
        with self.assertRaises(InvalidRealRecords):
            evaluate(body([{"a": 1}, {"b": 1}], [{"a": 1}], fields))
        with self.assertRaises(InvalidSyntheticRecords):
            evaluate(body([{"a": 1}], [{"a": 1}, {"b": 1}], fields))

    def test_container_target(self):
        fields = [field("/a", "numeric")]
        with self.assertRaises(InvalidRealRecords):
            evaluate(body([{"a": {"b": 1}}], [{"a": 1}], fields))
        with self.assertRaises(InvalidRealRecords):
            evaluate(body([{"a": [1]}], [{"a": 1}], fields))
        with self.assertRaises(InvalidSyntheticRecords):
            evaluate(body([{"a": 1}], [{"a": {"b": 1}}], fields))

    def test_categorical_type_mismatch(self):
        fields = [field("/a", "categorical")]
        for bad in (1, 1.5, [], {}):
            with self.subTest(bad=bad):
                with self.assertRaises(InvalidRealRecords):
                    evaluate(body([{"a": bad}], [{"a": "x"}], fields))
                with self.assertRaises(InvalidSyntheticRecords):
                    evaluate(body([{"a": "x"}], [{"a": bad}], fields))

    def test_numeric_type_mismatch(self):
        fields = [field("/a", "numeric")]
        for bad in ("1", None, True, False, [], {}):
            with self.subTest(bad=bad):
                with self.assertRaises(InvalidRealRecords):
                    evaluate(body([{"a": bad}], [{"a": 1}], fields))
                with self.assertRaises(InvalidSyntheticRecords):
                    evaluate(body([{"a": 1}], [{"a": bad}], fields))

    def test_nested_and_array_pointer_resolution(self):
        real = [{"profile": {"age": 30}, "vitals": [72]}]
        synthetic = [{"profile": {"age": 31}, "vitals": [74]}]
        response = evaluate(
            body(
                real,
                synthetic,
                [field("/profile/age", "numeric"), field("/vitals/0", "numeric")],
            )
        )
        self.assertEqual([f["path"] for f in response["fields"]], ["/profile/age", "/vitals/0"])

    def test_array_index_errors(self):
        fields = [field("/xs/0", "numeric")]
        with self.assertRaises(InvalidRealRecords):
            evaluate(body([{"xs": []}], [{"xs": [1]}], fields))
        with self.assertRaises(InvalidSyntheticRecords):
            evaluate(body([{"xs": [1]}], [{"xs": []}], fields))
        # Leading-zero indices and "-" are syntactically valid pointers that
        # fail at resolution time, so they surface as record errors.
        with self.assertRaises(InvalidRealRecords):
            evaluate(body([{"xs": [1]}], [{"xs": [1]}], [field("/xs/01", "numeric")]))
        with self.assertRaises(InvalidRealRecords):
            evaluate(body([{"xs": [1]}], [{"xs": [1]}], [field("/xs/-", "numeric")]))

    def test_escaped_pointer_segments(self):
        response = evaluate(
            body(
                [{"a/b": 1, "m~n": 9}],
                [{"a/b": 1, "m~n": 9}],
                [field("/a~1b", "numeric"), field("/m~0n", "numeric")],
            )
        )
        self.assertEqual(response["overall_utility"], 1.0)


class RequestShapeValidationTest(unittest.TestCase):
    def test_root_not_object(self):
        for payload in (None, [], "x", 1, True):
            with self.subTest(payload=payload):
                with self.assertRaises(InvalidRequest):
                    evaluate(payload)

    def test_missing_or_empty_arrays(self):
        good_real = [{"a": 1}]
        good_synth = [{"a": 1}]
        good_fields = [field("/a", "numeric")]
        cases = [
            {},
            {"synthetic_records": good_synth, "fields": good_fields},
            {"real_records": good_real, "fields": good_fields},
            {"real_records": good_real, "synthetic_records": good_synth},
            {"real_records": [], "synthetic_records": good_synth, "fields": good_fields},
            {"real_records": good_real, "synthetic_records": [], "fields": good_fields},
            {"real_records": good_real, "synthetic_records": good_synth, "fields": []},
            {"real_records": None, "synthetic_records": good_synth, "fields": good_fields},
            {"real_records": good_real, "synthetic_records": {}, "fields": good_fields},
            {"real_records": good_real, "synthetic_records": good_synth, "fields": "x"},
        ]
        for payload in cases:
            with self.subTest(payload=payload):
                with self.assertRaises(InvalidRequest):
                    evaluate(payload)

    def test_records_validated_before_fields_schema(self):
        # Bad root shape surfaces invalid_request, not invalid_schema.
        with self.assertRaises(InvalidRequest):
            evaluate(
                {
                    "real_records": [],
                    "synthetic_records": [{"a": 1}],
                    "fields": [field("/a", "bogus")],
                }
            )

    def test_schema_validated_before_record_resolution(self):
        # A malformed field is invalid_schema even though paths also fail.
        with self.assertRaises(InvalidSchema):
            evaluate(
                body(
                    [{"a": 1}],
                    [{"a": 1}],
                    [field("/missing", "bogus")],
                )
            )


class SyntheticHttpTest(unittest.TestCase):
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
        return self.request("POST", "/v1/synthetic/evaluate", body=raw, content_type=content_type)

    def test_happy_path(self):
        status, payload, _ = self.post(
            {
                "real_records": [{"g": "M", "n": 1}, {"g": "F", "n": 2}],
                "synthetic_records": [{"g": "M", "n": 1}, {"g": "F", "n": 8}],
                "fields": [{"path": "/g", "kind": "categorical"}, {"path": "/n", "kind": "numeric"}],
            }
        )
        self.assertEqual(status, 200)
        self.assertEqual(payload["real_count"], 2)
        self.assertEqual(payload["synthetic_count"], 2)
        self.assertEqual([f["path"] for f in payload["fields"]], ["/g", "/n"])
        self.assertEqual(payload["fields"][0]["distance"], 0.0)
        self.assertEqual(payload["fields"][1]["distance"], 0.5)
        self.assertEqual(payload["overall_utility"], 0.75)
        self.assertEqual(payload["exact_match_count"], 1)
        self.assertEqual(payload["exact_match_rate"], 0.5)
        blob = json.dumps(payload, ensure_ascii=False)
        self.assertNotIn("rare", blob)

    def test_method_not_allowed(self):
        for method in ("GET", "PUT", "DELETE", "PATCH"):
            with self.subTest(method=method):
                status, payload, allow = self.request(method, "/v1/synthetic/evaluate")
                self.assertEqual(status, 405)
                self.assertEqual(payload["error"]["code"], "method_not_allowed")
                self.assertEqual(allow, "POST")

    def test_unknown_path_still_404(self):
        status, payload, _ = self.request("POST", "/v1/nope")
        self.assertEqual(status, 404)
        self.assertEqual(payload["error"]["code"], "not_found")

    def test_unsupported_media_type(self):
        status, payload, _ = self.post({}, content_type="text/plain")
        self.assertEqual(status, 415)
        self.assertEqual(payload["error"]["code"], "unsupported_media_type")

    def test_invalid_json(self):
        status, payload, _ = self.post("{not json")
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"]["code"], "invalid_json")

    def test_invalid_request(self):
        for raw in ("[]", "{}", '{"real_records": []}', '{"real_records": [1]}'):
            with self.subTest(raw=raw):
                status, payload, _ = self.post(raw)
                self.assertEqual(status, 422)
                self.assertEqual(payload["error"]["code"], "invalid_request")

    def test_invalid_schema(self):
        cases = [
            body([{"a": 1}], [{"a": 1}], [{"path": "/a"}]),
            body([{"a": 1}], [{"a": 1}], [{"kind": "numeric"}]),
            body([{"a": 1}], [{"a": 1}], [field("/a", "nominal")]),
            body([{"a": 1}], [{"a": 1}], [field("", "numeric")]),
            body(
                [{"a": 1}],
                [{"a": 1}],
                [field("/a", "numeric"), field("/a", "numeric")],
            ),
        ]
        for payload in cases:
            with self.subTest(payload=payload):
                status, parsed, _ = self.post(payload)
                self.assertEqual(status, 422)
                self.assertEqual(parsed["error"]["code"], "invalid_schema")

    def test_invalid_real_records(self):
        cases = [
            body([1], [{"a": 1}], [field("/a", "numeric")]),
            body([{"b": 1}], [{"a": 1}], [field("/a", "numeric")]),
            body([{"a": {"b": 1}}], [{"a": 1}], [field("/a", "numeric")]),
            body([{"a": "x"}], [{"a": 1}], [field("/a", "numeric")]),
        ]
        for payload in cases:
            with self.subTest(payload=payload):
                status, parsed, _ = self.post(payload)
                self.assertEqual(status, 422)
                self.assertEqual(parsed["error"]["code"], "invalid_real_records")

    def test_invalid_synthetic_records(self):
        cases = [
            body([{"a": 1}], [1], [field("/a", "numeric")]),
            body([{"a": 1}], [{"b": 1}], [field("/a", "numeric")]),
            body([{"a": 1}], [{"a": [1]}], [field("/a", "numeric")]),
            body([{"a": 1}], [{"a": True}], [field("/a", "numeric")]),
            body([{"a": "x"}], [{"a": 1}], [field("/a", "categorical")]),
        ]
        for payload in cases:
            with self.subTest(payload=payload):
                status, parsed, _ = self.post(payload)
                self.assertEqual(status, 422)
                self.assertEqual(parsed["error"]["code"], "invalid_synthetic_records")

    def test_no_partial_results_on_failure(self):
        status, payload, _ = self.post(
            body([{"a": 1}], [{"b": 2}], [field("/a", "numeric")])
        )
        self.assertEqual(status, 422)
        self.assertNotIn("fields", payload)
        self.assertNotIn("overall_utility", payload)

    def test_healthz_unchanged(self):
        status, payload, _ = self.request("GET", "/healthz")
        self.assertEqual(status, 200)
        self.assertEqual(payload["status"], "ok")


if __name__ == "__main__":
    unittest.main()
