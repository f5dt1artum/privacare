import copy
import http.client
import json
import threading
import unittest
from http.server import ThreadingHTTPServer

from privacare.aggregator import InvalidGroupBy, InvalidMetric, InvalidThreshold
from privacare.classifier import InvalidRequest
from privacare.server import Handler
from privacare.service import Service


def aggregate(payload):
    return Service().aggregate(payload)


def body(records, group_by, metrics, minimum_group_size=2):
    return {
        "records": records,
        "group_by": group_by,
        "metrics": metrics,
        "minimum_group_size": minimum_group_size,
    }


COUNT_ONLY = [{"name": "n", "operation": "count"}]


class GroupingTest(unittest.TestCase):
    def test_grouping_first_appearance_order_and_suppression(self):
        records = [
            {"dept": "cardio", "fee": 10},
            {"dept": "neuro", "fee": 1},
            {"dept": "cardio", "fee": 20},
            {"dept": "neuro", "fee": 2},
            {"dept": "cardio", "fee": 30},
        ]
        metrics = [
            {"name": "cases", "operation": "count"},
            {"name": "total_fee", "operation": "sum", "field": "/fee"},
            {"name": "avg_fee", "operation": "average", "field": "/fee"},
        ]
        response = aggregate(body(records, ["/dept"], metrics, minimum_group_size=3))
        self.assertEqual(set(response), {"groups", "suppressed_group_count"})
        self.assertEqual(response["suppressed_group_count"], 1)
        self.assertEqual(len(response["groups"]), 1)
        group = response["groups"][0]
        self.assertEqual(set(group), {"key", "size", "metrics"})
        self.assertEqual(group["key"], ["cardio"])
        self.assertEqual(group["size"], 3)
        self.assertEqual(
            group["metrics"],
            {"cases": 3, "total_fee": 60.0, "avg_fee": 20.0},
        )

    def test_groups_follow_first_appearance_order(self):
        records = [{"g": "b"}, {"g": "a"}, {"g": "a"}, {"g": "b"}, {"g": "c"}, {"g": "c"}]
        response = aggregate(body(records, ["/g"], COUNT_ONLY))
        self.assertEqual([g["key"] for g in response["groups"]], [["b"], ["a"], ["c"]])
        self.assertEqual([g["size"] for g in response["groups"]], [2, 2, 2])
        self.assertEqual(response["suppressed_group_count"], 0)

    def test_global_grouping_with_empty_group_by(self):
        records = [{"v": 1}, {"v": 2}, {"v": 3}]
        response = aggregate(
            body(records, [], [{"name": "total", "operation": "sum", "field": "/v"}], 2)
        )
        self.assertEqual(len(response["groups"]), 1)
        group = response["groups"][0]
        self.assertEqual(group["key"], [])
        self.assertEqual(group["size"], 3)
        self.assertEqual(group["metrics"], {"total": 6.0})

    def test_global_group_below_threshold_is_suppressed(self):
        response = aggregate(body([{"v": 1}], [], COUNT_ONLY, minimum_group_size=2))
        self.assertEqual(response, {"groups": [], "suppressed_group_count": 1})

    def test_multi_pointer_keys_in_group_by_order(self):
        records = [
            {"a": 1, "b": "x"},
            {"b": "x", "a": 1},
            {"a": 1, "b": "y"},
            {"a": 1, "b": "y"},
        ]
        response = aggregate(body(records, ["/b", "/a"], COUNT_ONLY))
        self.assertEqual([g["key"] for g in response["groups"]], [["x", 1], ["y", 1]])

    def test_json_type_distinctions(self):
        records = [{"v": None}, {"v": None}, {"v": 0}, {"v": False}, {"v": 1}, {"v": True}]
        response = aggregate(body(records, ["/v"], COUNT_ONLY))
        self.assertEqual(response["suppressed_group_count"], 4)
        self.assertEqual([g["key"] for g in response["groups"]], [[None]])
        self.assertEqual(response["groups"][0]["size"], 2)

    def test_numbers_group_by_numeric_value(self):
        records = [{"n": 1}, {"n": 1.0}, {"n": 2.0}, {"n": 2}]
        response = aggregate(body(records, ["/n"], COUNT_ONLY))
        self.assertEqual([g["size"] for g in response["groups"]], [2, 2])
        # 首个出现的原始表示进入 key
        self.assertEqual([g["key"] for g in response["groups"]], [[1], [2.0]])

    def test_strings_are_case_sensitive(self):
        records = [{"s": "M"}, {"s": "m"}, {"s": "m"}]
        response = aggregate(body(records, ["/s"], COUNT_ONLY))
        self.assertEqual([g["key"] for g in response["groups"]], [["m"]])
        self.assertEqual(response["suppressed_group_count"], 1)

    def test_nested_pointers_and_escaped_segments(self):
        records = [
            {"profile": {"age": 30}, "a/b": 1},
            {"profile": {"age": 30}, "a/b": 1},
            {"profile": {"age": 31}, "a/b": 1},
        ]
        response = aggregate(body(records, ["/profile/age", "/a~1b"], COUNT_ONLY))
        self.assertEqual([g["key"] for g in response["groups"]], [[30, 1]])
        self.assertEqual(response["suppressed_group_count"], 1)

    def test_sum_and_average_round_half_up_to_six_places(self):
        # 1/3 = 0.333333... -> 0.333333; 10/6 = 1.666666... -> 1.666667
        metrics = [{"name": "avg", "operation": "average", "field": "/v"}]
        first = aggregate(body([{"v": 1}] * 3, [], metrics, minimum_group_size=2))
        self.assertEqual(first["groups"][0]["metrics"]["avg"], 1.0)
        second = aggregate(body([{"v": 10}] + [{"v": 0}] * 5, [], metrics, minimum_group_size=2))
        self.assertEqual(second["groups"][0]["metrics"]["avg"], 1.666667)

    def test_half_up_tie_at_seventh_decimal(self):
        # sum 5, size 8 -> 0.625 exactly; use 1/128 = 0.0078125 -> 0.007813
        records = [{"v": 1}] + [{"v": 0}] * 127
        metrics = [{"name": "avg", "operation": "average", "field": "/v"}]
        response = aggregate(body(records, [], metrics, minimum_group_size=2))
        self.assertEqual(response["groups"][0]["metrics"]["avg"], 0.007813)

    def test_sum_rounds_half_up(self):
        records = [{"v": 0.0000005}, {"v": 0}]
        metrics = [{"name": "total", "operation": "sum", "field": "/v"}]
        response = aggregate(body(records, [], metrics, minimum_group_size=2))
        self.assertEqual(response["groups"][0]["metrics"]["total"], 0.000001)

    def test_suppressed_groups_leak_nothing_but_count(self):
        secret = "rare-disease-cohort"
        records = [{"dx": secret, "v": 42}, {"dx": "common", "v": 1}, {"dx": "common", "v": 2}]
        response = aggregate(
            body(records, ["/dx"], [{"name": "t", "operation": "sum", "field": "/v"}])
        )
        blob = json.dumps(response, ensure_ascii=False)
        self.assertNotIn(secret, blob)
        self.assertNotIn("42", blob)
        self.assertEqual(response["suppressed_group_count"], 1)
        self.assertEqual(len(response["groups"]), 1)

    def test_deterministic_and_input_not_mutated(self):
        payload = body(
            [{"a": 1, "v": 2}, {"a": 1, "v": 3}, {"a": 2, "v": 9}],
            ["/a"],
            [{"name": "s", "operation": "sum", "field": "/v"}],
        )
        snapshot = copy.deepcopy(payload)
        first = aggregate(payload)
        second = aggregate(payload)
        self.assertEqual(first, second)
        self.assertEqual(payload, snapshot)


class GroupByValidationTest(unittest.TestCase):
    def test_not_an_array(self):
        for raw in (None, "x", 1, {"/a": 1}):
            with self.subTest(raw=raw):
                with self.assertRaises(InvalidGroupBy):
                    aggregate(body([{"a": 1}], raw, COUNT_ONLY))

    def test_non_string_entries_and_duplicates(self):
        for group_by in ([1], [None], ["/a", "/a"], [["/a"]]):
            with self.subTest(group_by=group_by):
                with self.assertRaises(InvalidGroupBy):
                    aggregate(body([{"a": 1}], group_by, COUNT_ONLY))

    def test_invalid_pointer_syntax(self):
        for pointer in ("a", "/a~2", "/a~"):
            with self.subTest(pointer=pointer):
                with self.assertRaises(InvalidGroupBy):
                    aggregate(body([{"a": 1}], [pointer], COUNT_ONLY))

    def test_pointer_resolution_failures(self):
        cases = [
            ([{"a": 1}], ["/b"]),                        # missing key
            ([{"a": 1}], ["/a/x"]),                     # descent into scalar
            ([{"xs": [1]}], ["/xs/2"]),                 # array out of bounds
            ([{"xs": [1]}], ["/xs/-"]),                 # RFC index, never resolves
            ([{"xs": [1]}], ["/xs/01"]),                # leading zero
            ([{"a": {"b": 1}}], ["/a"]),                # object container
            ([{"a": [1]}], ["/a"]),                     # array container
            ([{"a": 1}, {"b": 1}], ["/a"]),             # missing on one record
            ([{"a": 1}], [""]),                         # root pointer hits the record container
        ]
        for records, group_by in cases:
            with self.subTest(group_by=group_by):
                with self.assertRaises(InvalidGroupBy):
                    aggregate(body(records, group_by, COUNT_ONLY))

    def test_empty_key_pointer_is_valid(self):
        response = aggregate(body([{"": 5}, {"": 5}], ["/"], COUNT_ONLY))
        self.assertEqual(response["groups"][0]["key"], [5])


class MetricValidationTest(unittest.TestCase):
    def test_metrics_not_a_non_empty_array(self):
        for raw in (None, [], "x", {}):
            with self.subTest(raw=raw):
                with self.assertRaises(InvalidMetric):
                    aggregate(body([{"a": 1}], ["/a"], raw))

    def test_metric_must_be_object_with_unique_non_empty_name(self):
        bad_metrics = [
            [1],
            [{"operation": "count"}],
            [{"name": "", "operation": "count"}],
            [{"name": 1, "operation": "count"}],
            [{"name": "m", "operation": "count"}, {"name": "m", "operation": "count"}],
        ]
        for metrics in bad_metrics:
            with self.subTest(metrics=metrics):
                with self.assertRaises(InvalidMetric):
                    aggregate(body([{"a": 1}], ["/a"], metrics))

    def test_operation_must_be_known(self):
        for operation in (None, "median", "SUM", 1):
            with self.subTest(operation=operation):
                with self.assertRaises(InvalidMetric):
                    aggregate(body([{"a": 1}], ["/a"], [{"name": "m", "operation": operation}]))

    def test_count_must_not_carry_field(self):
        metrics = [{"name": "m", "operation": "count", "field": "/a"}]
        with self.assertRaises(InvalidMetric):
            aggregate(body([{"a": 1}], ["/a"], metrics))

    def test_sum_and_average_require_a_non_root_pointer_field(self):
        for field in (None, 1, "", "a", "/a~2"):
            for operation in ("sum", "average"):
                metrics = [{"name": "m", "operation": operation, "field": field}]
                with self.subTest(operation=operation, field=field):
                    with self.assertRaises(InvalidMetric):
                        aggregate(body([{"a": 1}], ["/a"], metrics))

    def test_field_must_resolve_to_finite_numbers_everywhere(self):
        cases = [
            [{"a": 1}, {"b": 2}],          # missing on one record
            [{"a": "1"}],                  # string is not a number
            [{"a": True}],                 # boolean is not a number
            [{"a": None}],                 # null is not a number
            [{"a": {"b": 1}}],             # container
            [{"a": [1]}],                  # container
        ]
        for records in cases:
            with self.subTest(records=records):
                with self.assertRaises(InvalidMetric):
                    aggregate(
                        body(records, [], [{"name": "m", "operation": "sum", "field": "/a"}])
                    )

    def test_field_non_finite_number_rejected(self):
        payload = body(
            [{"a": float("nan")}, {"a": 1}],
            [],
            [{"name": "m", "operation": "sum", "field": "/a"}],
        )
        with self.assertRaises(InvalidMetric):
            aggregate(payload)


class ThresholdValidationTest(unittest.TestCase):
    def test_invalid_threshold(self):
        for value in (None, True, False, 1, 0, -1, 1001, 2.0, 2.5, "2", [2]):
            with self.subTest(value=value):
                with self.assertRaises(InvalidThreshold):
                    aggregate(body([{"a": 1}, {"a": 1}], ["/a"], COUNT_ONLY, value))

    def test_boundaries_accepted(self):
        for value in (2, 1000):
            with self.subTest(value=value):
                response = aggregate(body([{"a": 1}] * value, ["/a"], COUNT_ONLY, value))
                self.assertEqual(response["groups"][0]["size"], value)


class RequestShapeValidationTest(unittest.TestCase):
    def test_invalid_request(self):
        for payload in (
            None,
            [],
            "x",
            {},
            {"records": None},
            {"records": []},
            {"records": [1]},
            {"records": ["s"]},
        ):
            with self.subTest(payload=payload):
                with self.assertRaises(InvalidRequest):
                    aggregate(payload)

    def test_records_validated_before_other_fields(self):
        with self.assertRaises(InvalidRequest):
            aggregate({"records": [1], "group_by": "bad", "metrics": "bad"})


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
                    {"dept": "cardio", "fee": 10},
                    {"dept": "cardio", "fee": 20},
                    {"dept": "neuro", "fee": 99},
                ],
                "group_by": ["/dept"],
                "metrics": [
                    {"name": "cases", "operation": "count"},
                    {"name": "avg_fee", "operation": "average", "field": "/fee"},
                ],
                "minimum_group_size": 2,
            }
        )
        self.assertEqual(status, 200)
        self.assertEqual(set(payload), {"groups", "suppressed_group_count"})
        self.assertEqual(payload["suppressed_group_count"], 1)
        self.assertEqual(len(payload["groups"]), 1)
        group = payload["groups"][0]
        self.assertEqual(group["key"], ["cardio"])
        self.assertEqual(group["size"], 2)
        self.assertEqual(group["metrics"], {"cases": 2, "avg_fee": 15.0})
        blob = json.dumps(payload, ensure_ascii=False)
        self.assertNotIn("neuro", blob)
        self.assertNotIn("99", blob)

    def test_method_not_allowed(self):
        for method in ("GET", "PUT", "DELETE", "PATCH"):
            with self.subTest(method=method):
                status, payload, allow = self.request(method, "/v1/query/aggregate")
                self.assertEqual(status, 405)
                self.assertEqual(payload["error"]["code"], "method_not_allowed")
                self.assertEqual(allow, "POST")

    def test_unknown_path_still_404(self):
        for method, path in (("POST", "/v1/query"), ("GET", "/nope")):
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

    def test_invalid_group_by(self):
        cases = [
            {"records": [{"a": 1}], "group_by": "x", "metrics": COUNT_ONLY, "minimum_group_size": 2},
            {"records": [{"a": 1}], "group_by": ["/a", "/a"], "metrics": COUNT_ONLY, "minimum_group_size": 2},
            {"records": [{"a": 1}], "group_by": ["/b"], "metrics": COUNT_ONLY, "minimum_group_size": 2},
            {"records": [{"a": {"b": 1}}], "group_by": ["/a"], "metrics": COUNT_ONLY, "minimum_group_size": 2},
        ]
        for payload in cases:
            with self.subTest(payload=payload):
                status, parsed, _ = self.post(payload)
                self.assertEqual(status, 422)
                self.assertEqual(parsed["error"]["code"], "invalid_group_by")

    def test_invalid_metric(self):
        cases = [
            {"records": [{"a": 1}], "group_by": [], "metrics": [], "minimum_group_size": 2},
            {"records": [{"a": 1}], "group_by": [], "metrics": [{"name": "m", "operation": "median"}], "minimum_group_size": 2},
            {"records": [{"a": 1}], "group_by": [], "metrics": [{"name": "m", "operation": "sum"}], "minimum_group_size": 2},
            {"records": [{"a": 1}], "group_by": [], "metrics": [{"name": "m", "operation": "sum", "field": "/b"}], "minimum_group_size": 2},
            {"records": [{"a": "x"}], "group_by": [], "metrics": [{"name": "m", "operation": "average", "field": "/a"}], "minimum_group_size": 2},
        ]
        for payload in cases:
            with self.subTest(payload=payload):
                status, parsed, _ = self.post(payload)
                self.assertEqual(status, 422)
                self.assertEqual(parsed["error"]["code"], "invalid_metric")

    def test_invalid_threshold(self):
        for value in ("true", "1", "1001", "1.5", '"2"'):
            with self.subTest(value=value):
                status, payload, _ = self.post(
                    '{"records": [{"a": 1}], "group_by": ["/a"], '
                    '"metrics": [{"name": "m", "operation": "count"}], '
                    '"minimum_group_size": %s}' % value
                )
                self.assertEqual(status, 422)
                self.assertEqual(payload["error"]["code"], "invalid_threshold")

    def test_no_partial_results_on_failure(self):
        status, payload, _ = self.post(
            {
                "records": [{"a": 1}, {"b": 2}],
                "group_by": ["/a"],
                "metrics": COUNT_ONLY,
                "minimum_group_size": 2,
            }
        )
        self.assertEqual(status, 422)
        self.assertNotIn("groups", payload)
        self.assertNotIn("suppressed_group_count", payload)

    def test_healthz_and_existing_endpoints_unchanged(self):
        status, payload, _ = self.request("GET", "/healthz")
        self.assertEqual(status, 200)
        self.assertEqual(payload["status"], "ok")
        status, payload, _ = self.request(
            "POST", "/v1/classify", body=json.dumps({"records": [{"note": "x"}]}),
            content_type="application/json",
        )
        self.assertEqual(status, 200)
        self.assertIn("results", payload)


if __name__ == "__main__":
    unittest.main()
