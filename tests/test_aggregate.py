import copy
import http.client
import json
import threading
import unittest
from http.server import ThreadingHTTPServer

from privacare.aggregate import (
    InvalidGroupBy,
    InvalidMetric,
    InvalidThreshold,
    aggregate_query_request,
)
from privacare.classifier import InvalidRequest
from privacare.server import Handler
from privacare.service import Service


def run(payload):
    return Service().aggregate_query(payload)


def body(records, group_by, metrics, minimum_group_size=2):
    return {
        "records": records,
        "group_by": group_by,
        "metrics": metrics,
        "minimum_group_size": minimum_group_size,
    }


COUNT = {"name": "n", "operation": "count"}


class AggregateHappyPathTest(unittest.TestCase):
    def test_grouping_count_sum_average(self):
        records = [
            {"city": "BJ", "age": 30, "v": 1.5},
            {"city": "BJ", "age": 40, "v": 2.5},
            {"city": "SH", "age": 50, "v": 9.0},
        ]
        metrics = [
            COUNT,
            {"name": "total_age", "operation": "sum", "field": "/age"},
            {"name": "avg_v", "operation": "average", "field": "/v"},
        ]
        response = run(body(records, ["/city"], metrics))
        self.assertEqual(
            set(response), {"groups", "suppressed_group_count"}
        )
        self.assertEqual(response["suppressed_group_count"], 1)
        groups = response["groups"]
        self.assertEqual(len(groups), 1)
        group = groups[0]
        self.assertEqual(set(group), {"key", "size", "metrics"})
        self.assertEqual(group["key"], ["BJ"])
        self.assertEqual(group["size"], 2)
        self.assertEqual(
            group["metrics"], {"n": 2, "total_age": 70.0, "avg_v": 2.0}
        )

    def test_global_grouping_with_empty_group_by(self):
        records = [{"v": 1}, {"v": 2}, {"v": 3}]
        response = run(body(records, [], [{"name": "avg_v", "operation": "average", "field": "/v"}]))
        self.assertEqual(response["suppressed_group_count"], 0)
        self.assertEqual(len(response["groups"]), 1)
        group = response["groups"][0]
        self.assertEqual(group["key"], [])
        self.assertEqual(group["size"], 3)
        self.assertEqual(group["metrics"], {"avg_v": 2.0})

    def test_groups_in_first_appearance_order(self):
        records = [
            {"g": "b"}, {"g": "a"}, {"g": "b"}, {"g": "a"}, {"g": "c"}
        ]
        response = run(body(records, ["/g"], [COUNT]))
        self.assertEqual([g["key"] for g in response["groups"]], [["b"], ["a"]])
        self.assertEqual(response["suppressed_group_count"], 1)

    def test_threshold_boundary(self):
        records = [{"g": 1}, {"g": 1}, {"g": 2}, {"g": 2}, {"g": 2}]
        below = run(body(records, ["/g"], [COUNT], minimum_group_size=3))
        self.assertEqual([g["key"] for g in below["groups"]], [[2]])
        self.assertEqual(below["suppressed_group_count"], 1)
        at = run(body(records, ["/g"], [COUNT], minimum_group_size=2))
        self.assertEqual(len(at["groups"]), 2)
        self.assertEqual(at["suppressed_group_count"], 0)
        top = run(body(records, ["/g"], [COUNT], minimum_group_size=1000))
        self.assertEqual(top["groups"], [])
        self.assertEqual(top["suppressed_group_count"], 2)

    def test_null_false_and_zero_are_distinct_keys(self):
        records = [
            {"g": None}, {"g": None},
            {"g": False}, {"g": False},
            {"g": 0}, {"g": 0},
        ]
        response = run(body(records, ["/g"], [COUNT]))
        self.assertEqual([g["key"] for g in response["groups"]], [[None], [False], [0]])
        self.assertEqual(response["suppressed_group_count"], 0)

    def test_boolean_not_equal_to_one_and_numeric_equality(self):
        records = [{"g": True}, {"g": True}, {"g": 1}, {"g": 1.0}]
        response = run(body(records, ["/g"], [COUNT]))
        self.assertEqual([g["key"] for g in response["groups"]], [[True], [1]])
        self.assertEqual([g["size"] for g in response["groups"]], [2, 2])

    def test_strings_are_case_sensitive(self):
        records = [{"g": "M"}, {"g": "m"}, {"g": "M"}]
        response = run(body(records, ["/g"], [COUNT]))
        self.assertEqual(response["suppressed_group_count"], 1)
        self.assertEqual(response["groups"][0]["key"], ["M"])
        self.assertEqual(response["groups"][0]["size"], 2)

    def test_composite_key_keeps_group_by_order(self):
        records = [
            {"a": 1, "b": "x"}, {"a": 1, "b": "x"},
            {"a": 1, "b": "y"}, {"a": 0, "b": "x"},
        ]
        response = run(body(records, ["/a", "/b"], [COUNT]))
        self.assertEqual([g["key"] for g in response["groups"]], [[1, "x"]])
        self.assertEqual(response["suppressed_group_count"], 2)

    def test_nested_pointers_array_indices_and_escapes(self):
        records = [
            {"profile": {"city": "BJ"}, "rows": [{"v": 1}, {"v": 2}], "a/b": 7},
            {"profile": {"city": "BJ"}, "rows": [{"v": 3}, {"v": 4}], "a/b": 7},
        ]
        metrics = [
            {"name": "s", "operation": "sum", "field": "/rows/0/v"},
            {"name": "t", "operation": "sum", "field": "/a~1b"},
        ]
        response = run(body(records, ["/profile/city"], metrics))
        self.assertEqual(response["groups"][0]["metrics"], {"s": 4.0, "t": 14.0})

    def test_sum_half_up_rounding_and_decimal_arithmetic(self):
        records = [{"g": "a", "v": 1.1}, {"g": "a", "v": 2.2}]
        response = run(body(records, ["/g"], [{"name": "s", "operation": "sum", "field": "/v"}]))
        self.assertEqual(response["groups"][0]["metrics"]["s"], 3.3)

    def test_average_half_up_tie_and_repeating_fraction(self):
        # 1/6 = 0.166666... -> 0.166667
        records = [{"g": "a", "v": 1}] + [{"g": "a", "v": 0}] * 5
        response = run(body(records, ["/g"], [{"name": "avg", "operation": "average", "field": "/v"}]))
        self.assertEqual(response["groups"][0]["metrics"]["avg"], 0.166667)
        # 0.0000005 tie at the seventh digit: half up -> 0.000001
        tied = [{"g": "a", "v": 0.0000005}, {"g": "a", "v": 0.0000005}]
        tied_response = run(
            body(tied, ["/g"], [{"name": "avg", "operation": "average", "field": "/v"}])
        )
        self.assertEqual(tied_response["groups"][0]["metrics"]["avg"], 0.000001)

    def test_suppressed_groups_leak_nothing(self):
        secret = "rare-disease-label"
        records = [
            {"g": "common", "v": 1}, {"g": "common", "v": 2},
            {"g": secret, "v": 99},
        ]
        metrics = [COUNT, {"name": "s", "operation": "sum", "field": "/v"}]
        blob = json.dumps(run(body(records, ["/g"], metrics)), ensure_ascii=False)
        self.assertNotIn(secret, blob)
        self.assertNotIn("99", blob)

    def test_deterministic_and_input_not_mutated(self):
        payload = body(
            [{"g": "a", "v": 1}, {"g": "a", "v": 2}, {"g": "b", "v": 3}],
            ["/g"],
            [COUNT, {"name": "s", "operation": "sum", "field": "/v"}],
        )
        snapshot = copy.deepcopy(payload)
        first = run(payload)
        second = run(payload)
        self.assertEqual(first, second)
        self.assertEqual(payload, snapshot)


class GroupByValidationTest(unittest.TestCase):
    def test_missing_or_wrong_type(self):
        records = [{"a": 1}]
        for raw in (None, "x", {}, 1, [1], ["/a", 2], [None]):
            with self.subTest(raw=raw):
                with self.assertRaises(InvalidGroupBy):
                    run({"records": records, "group_by": raw, "metrics": [COUNT], "minimum_group_size": 2})

    def test_empty_array_is_global_grouping_not_an_error(self):
        response = run({"records": [{"a": 1}, {"a": 2}], "group_by": [], "metrics": [COUNT], "minimum_group_size": 2})
        self.assertEqual(response["groups"][0]["key"], [])

    def test_duplicates_rejected(self):
        with self.assertRaises(InvalidGroupBy):
            run(body([{"a": 1}], ["/a", "/a"], [COUNT]))

    def test_bad_pointer_syntax(self):
        for pointer in ("a", "/a~2", "/a~"):
            with self.subTest(pointer=pointer):
                with self.assertRaises(InvalidGroupBy):
                    run(body([{"a": 1}], [pointer], [COUNT]))

    def test_root_pointer_points_at_container(self):
        with self.assertRaises(InvalidGroupBy):
            run(body([{"a": 1}], [""], [COUNT]))

    def test_unresolved_or_container_values(self):
        cases = [
            ([{"a": 1}], ["/b"]),
            ([{"a": 1}], ["/a/x"]),
            ([{"xs": [1]}], ["/xs/2"]),
            ([{"xs": [1]}], ["/xs/-"]),
            ([{"xs": [1]}], ["/xs/01"]),
            ([{"a": {"b": 1}}], ["/a"]),
            ([{"a": [1]}], ["/a"]),
            ([{"a": 1}, {"b": 1}], ["/a"]),
        ]
        for records, pointers in cases:
            with self.subTest(pointers=pointers):
                with self.assertRaises(InvalidGroupBy):
                    run(body(records, pointers, [COUNT]))

    def test_non_finite_group_value_rejected_in_process(self):
        with self.assertRaises(InvalidGroupBy):
            run(body([{"a": float("nan")}, {"a": float("nan")}], ["/a"], [COUNT]))


class MetricValidationTest(unittest.TestCase):
    def test_metrics_must_be_non_empty_array_of_objects(self):
        records = [{"a": 1}]
        for raw in (None, [], "x", [1], ["x"], [None]):
            with self.subTest(raw=raw):
                with self.assertRaises(InvalidMetric):
                    run(body(records, [], raw))

    def test_names_unique_and_non_empty(self):
        for name in (None, "", 1, ["x"], {"x": 1}):
            with self.subTest(name=name):
                with self.assertRaises(InvalidMetric):
                    run(body([{"a": 1}], [], [{"name": name, "operation": "count"}]))
        with self.assertRaises(InvalidMetric):
            run(body([{"a": 1}], [], [
                {"name": "dup", "operation": "count"},
                {"name": "dup", "operation": "count"},
            ]))

    def test_operation_must_be_known(self):
        for operation in (None, "", "COUNT", "median", 1):
            with self.subTest(operation=operation):
                with self.assertRaises(InvalidMetric):
                    run(body([{"a": 1}], [], [{"name": "m", "operation": operation}]))

    def test_count_must_not_carry_field(self):
        with self.assertRaises(InvalidMetric):
            run(body([{"a": 1}], [], [{"name": "m", "operation": "count", "field": "/a"}]))
        with self.assertRaises(InvalidMetric):
            run(body([{"a": 1}], [], [{"name": "m", "operation": "count", "field": None}]))

    def test_sum_and_average_require_non_root_pointer(self):
        for field in (None, "", "a", "/a~x", 1):
            with self.subTest(field=field):
                with self.assertRaises(InvalidMetric):
                    run(body([{"a": 1}], [], [{"name": "m", "operation": "sum", "field": field}]))
        with self.assertRaises(InvalidMetric):
            run(body([{"a": 1}], [], [{"name": "m", "operation": "average", "field": "/"}]))

    def test_field_must_resolve_on_every_record(self):
        with self.assertRaises(InvalidMetric):
            run(body([{"v": 1}, {"w": 2}], [], [{"name": "s", "operation": "sum", "field": "/v"}]))

    def test_field_must_be_finite_number_not_bool_or_string_or_null(self):
        for value in (True, False, "1", None, [1], {"x": 1}):
            with self.subTest(value=value):
                with self.assertRaises(InvalidMetric):
                    run(body([{"v": value}], [], [{"name": "s", "operation": "sum", "field": "/v"}]))

    def test_non_finite_number_rejected_in_process(self):
        with self.assertRaises(InvalidMetric):
            run(body([{"v": float("inf")}], [], [{"name": "s", "operation": "sum", "field": "/v"}]))


class ThresholdValidationTest(unittest.TestCase):
    def test_invalid_threshold(self):
        records = [{"a": 1}]
        for raw in (None, True, False, 1, 0, -2, 1.5, 2.0, "2", [2], 1001):
            with self.subTest(raw=raw):
                with self.assertRaises(InvalidThreshold):
                    run({"records": records, "group_by": [], "metrics": [COUNT], "minimum_group_size": raw})

    def test_missing_threshold(self):
        with self.assertRaises(InvalidThreshold):
            run({"records": [{"a": 1}], "group_by": [], "metrics": [COUNT]})

    def test_boundaries_2_and_1000_accepted(self):
        records = [{"a": 1}, {"a": 1}]
        run({"records": records, "group_by": ["/a"], "metrics": [COUNT], "minimum_group_size": 2})
        run({"records": records, "group_by": ["/a"], "metrics": [COUNT], "minimum_group_size": 1000})


class RequestShapeValidationTest(unittest.TestCase):
    def test_invalid_request(self):
        good = {"group_by": [], "metrics": [COUNT], "minimum_group_size": 2}
        for payload in (
            None, [], "x", {},
            {**good, "records": None},
            {**good, "records": []},
            {**good, "records": [1]},
            {**good, "records": ["s"]},
        ):
            with self.subTest(payload=payload):
                with self.assertRaises(InvalidRequest):
                    run(payload)

    def test_records_validated_before_group_by_and_metrics(self):
        with self.assertRaises(InvalidRequest):
            run({"records": [1], "group_by": ["/missing"], "metrics": [COUNT], "minimum_group_size": 2})

    def test_validation_order_group_by_metrics_threshold(self):
        records = [{"a": 1}]
        with self.assertRaises(InvalidGroupBy):
            run({"records": records, "group_by": ["bad"], "metrics": [COUNT], "minimum_group_size": 1})
        with self.assertRaises(InvalidMetric):
            run({"records": records, "group_by": [], "metrics": [], "minimum_group_size": 1})


class AggregateHttpTest(unittest.TestCase):
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
        return self.request("POST", "/v1/query/aggregate", body=raw, content_type=content_type)

    def test_happy_path(self):
        status, payload, _ = self.post(
            {
                "records": [
                    {"city": "BJ", "v": 1},
                    {"city": "BJ", "v": 3},
                    {"city": "SH", "v": 9},
                ],
                "group_by": ["/city"],
                "metrics": [
                    {"name": "n", "operation": "count"},
                    {"name": "avg_v", "operation": "average", "field": "/v"},
                ],
                "minimum_group_size": 2,
            }
        )
        self.assertEqual(status, 200)
        self.assertEqual(set(payload), {"groups", "suppressed_group_count"})
        self.assertEqual(payload["suppressed_group_count"], 1)
        self.assertEqual(
            payload["groups"],
            [{"key": ["BJ"], "size": 2, "metrics": {"n": 2, "avg_v": 2.0}}],
        )

    def test_response_is_not_wrapped_in_results(self):
        status, payload, _ = self.post(
            {
                "records": [{"v": 1}, {"v": 2}],
                "group_by": [],
                "metrics": [{"name": "n", "operation": "count"}],
                "minimum_group_size": 2,
            }
        )
        self.assertEqual(status, 200)
        self.assertNotIn("results", payload)

    def test_method_not_allowed(self):
        for method in ("GET", "PUT", "DELETE", "PATCH"):
            with self.subTest(method=method):
                status, payload, allow = self.request(method, "/v1/query/aggregate")
                self.assertEqual(status, 405)
                self.assertEqual(payload["error"]["code"], "method_not_allowed")
                self.assertEqual(allow, "POST")

    def test_unknown_path_still_404(self):
        status, payload, _ = self.request("POST", "/v1/query/nope")
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

    def test_error_codes(self):
        cases = [
            (
                "invalid_request",
                {"records": [], "group_by": [], "metrics": [{"name": "n", "operation": "count"}], "minimum_group_size": 2},
            ),
            (
                "invalid_group_by",
                {"records": [{"a": 1}], "group_by": ["/b"], "metrics": [{"name": "n", "operation": "count"}], "minimum_group_size": 2},
            ),
            (
                "invalid_metric",
                {"records": [{"a": 1}], "group_by": [], "metrics": [{"name": "n", "operation": "sum"}], "minimum_group_size": 2},
            ),
            (
                "invalid_threshold",
                {"records": [{"a": 1}], "group_by": [], "metrics": [{"name": "n", "operation": "count"}], "minimum_group_size": 1},
            ),
        ]
        for code, payload in cases:
            with self.subTest(code=code):
                status, parsed, _ = self.post(payload)
                self.assertEqual(status, 422)
                self.assertEqual(parsed["error"]["code"], code)

    def test_boolean_threshold_rejected_over_json(self):
        status, payload, _ = self.post(
            '{"records": [{"a": 1}], "group_by": [], '
            '"metrics": [{"name": "n", "operation": "count"}], "minimum_group_size": true}'
        )
        self.assertEqual(status, 422)
        self.assertEqual(payload["error"]["code"], "invalid_threshold")

    def test_no_partial_results_on_failure(self):
        status, payload, _ = self.post(
            {
                "records": [{"v": 1}, {"v": "x"}],
                "group_by": [],
                "metrics": [{"name": "s", "operation": "sum", "field": "/v"}],
                "minimum_group_size": 2,
            }
        )
        self.assertEqual(status, 422)
        self.assertNotIn("groups", payload)
        self.assertNotIn("suppressed_group_count", payload)


if __name__ == "__main__":
    unittest.main()
