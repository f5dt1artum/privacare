import base64
import copy
import http.client
import json
import threading
import unittest
from http.server import ThreadingHTTPServer

from privacare.classifier import InvalidRequest
from privacare.aggregate import InvalidGroupBy, InvalidMetric
from privacare.differential import (
    InvalidNoiseConfig,
    InvalidPartition,
    InvalidPrivacyBudget,
    _laplace_noise,
    differential_aggregate_request,
)
from privacare.server import Handler
from privacare.service import Service

SECRET = base64.urlsafe_b64encode(b"n" * 32).rstrip(b"=").decode("ascii")
OTHER_SECRET = base64.urlsafe_b64encode(b"m" * 32).rstrip(b"=").decode("ascii")


def run(payload):
    return Service().differential_aggregate(payload)


def body(records, **overrides):
    payload = {
        "records": records,
        "group_by": ["/g"],
        "partitions": [["a"], ["b"]],
        "metrics": [{"name": "n", "operation": "count", "epsilon": 1}],
        "budget": {"limit": 100, "spent": 0},
        "release_id": "release-1",
        "noise_secret": SECRET,
    }
    payload.update(overrides)
    return payload


COUNT = {"name": "n", "operation": "count", "epsilon": 1}


class DifferentialHappyPathTest(unittest.TestCase):
    def test_partitions_in_input_order_with_zero_count(self):
        records = [{"g": "b"}, {"g": "b"}, {"g": "c"}]
        response = run(body(records))
        self.assertEqual(set(response), {"partitions", "consumed", "spent", "remaining"})
        self.assertEqual([p["key"] for p in response["partitions"]], [["a"], ["b"]])
        self.assertEqual(set(response["partitions"][0]), {"key", "metrics"})
        self.assertEqual(set(response["partitions"][0]["metrics"]), {"n"})

    def test_unmatched_records_ignored(self):
        # "c" matches no public partition; with a huge epsilon the noisy
        # counts stay within 0.5 of the true counts 0 and 2.
        records = [{"g": "b"}, {"g": "b"}, {"g": "c"}, {"g": "c"}, {"g": "c"}]
        response = run(body(records, metrics=[{"name": "n", "operation": "count", "epsilon": 10}]))
        a, b = response["partitions"]
        self.assertAlmostEqual(a["metrics"]["n"], 0, delta=0.5)
        self.assertAlmostEqual(b["metrics"]["n"], 2, delta=0.5)

    def test_budget_accounting(self):
        metrics = [
            {"name": "n", "operation": "count", "epsilon": 0.5},
            {"name": "s", "operation": "sum", "field": "/v", "lower": 0, "upper": 10, "epsilon": 1.5},
        ]
        records = [{"g": "a", "v": 1}]
        response = run(body(records, metrics=metrics, budget={"limit": 10, "spent": 3}))
        self.assertEqual(response["consumed"], 2.0)
        self.assertEqual(response["spent"], 5.0)
        self.assertEqual(response["remaining"], 5.0)

    def test_consumed_does_not_scale_with_partitions(self):
        payload = body([{"g": "a"}], partitions=[["a"], ["b"], ["c"], ["d"]])
        response = run(payload)
        self.assertEqual(response["consumed"], 1.0)

    def test_exact_balance_is_allowed(self):
        response = run(body([{"g": "a"}], budget={"limit": 1.5, "spent": 0.5}))
        self.assertEqual(response["remaining"], 0.0)

    def test_sum_clamps_to_bounds(self):
        metrics = [
            {"name": "s", "operation": "sum", "field": "/v", "lower": 0, "upper": 1, "epsilon": 10}
        ]
        records = [{"g": "a", "v": -5}, {"g": "a", "v": 25}, {"g": "a", "v": 0.5}]
        response = run(body(records, partitions=[["a"]], metrics=metrics))
        # clamped sum is 0 + 1 + 0.5 = 1.5; noise scale 0.1 stays below 0.5.
        self.assertAlmostEqual(response["partitions"][0]["metrics"]["s"], 1.5, delta=0.5)

    def test_negative_noisy_count_returns_zero(self):
        # Find a release whose deterministic noise for this key/metric is
        # negative, then assert the published count is clamped to zero.
        secret = base64.urlsafe_b64decode(SECRET + "=")
        release = None
        for candidate in ("r0", "r1", "r2", "r3", "r4"):
            if _laplace_noise(secret, candidate, ((3, "a"),), "n", 10.0) < 0:
                release = candidate
                break
        self.assertIsNotNone(release)
        response = run(body([{"g": "b"}], partitions=[["a"]], release_id=release,
                            metrics=[{"name": "n", "operation": "count", "epsilon": 0.1}]))
        self.assertEqual(response["partitions"][0]["metrics"]["n"], 0.0)

    def test_empty_group_by_uses_empty_partition_keys(self):
        response = run(body([{"v": 1}, {"v": 2}], group_by=[], partitions=[[]]))
        self.assertEqual([p["key"] for p in response["partitions"]], [[]])

    def test_numeric_key_equality_one_and_one_point_zero(self):
        records = [{"g": 1}, {"g": 1.0}]
        response = run(body(records, partitions=[[1.0]],
                            metrics=[{"name": "n", "operation": "count", "epsilon": 10}]))
        self.assertAlmostEqual(response["partitions"][0]["metrics"]["n"], 2, delta=0.5)

    def test_null_false_and_zero_are_distinct_partition_keys(self):
        response = run(body([{"g": None}], partitions=[[None], [False], [0]]))
        self.assertEqual([p["key"] for p in response["partitions"]], [[None], [False], [0]])

    def test_deterministic_retry_and_input_not_mutated(self):
        payload = body([{"g": "a", "v": 1}, {"g": "b", "v": 2}],
                       metrics=[COUNT,
                                {"name": "s", "operation": "sum", "field": "/v",
                                 "lower": 0, "upper": 10, "epsilon": 2}])
        snapshot = copy.deepcopy(payload)
        first = run(payload)
        second = run(payload)
        self.assertEqual(first, second)
        self.assertEqual(payload, snapshot)

    def test_different_release_id_draws_independent_noise(self):
        records = [{"g": "a"}] * 5
        one = run(body(records, partitions=[["a"]], release_id="release-a"))
        two = run(body(records, partitions=[["a"]], release_id="release-b"))
        three = run(body(records, partitions=[["a"]], noise_secret=OTHER_SECRET))
        self.assertNotEqual(one["partitions"], two["partitions"])
        self.assertNotEqual(one["partitions"], three["partitions"])

    def test_response_does_not_echo_records_or_secret(self):
        secret_value = "rare-disease-label"
        records = [{"g": "a", "note": secret_value, "v": 12345}]
        metrics = [
            COUNT,
            {"name": "s", "operation": "sum", "field": "/v", "lower": 0, "upper": 10, "epsilon": 1},
        ]
        blob = json.dumps(run(body(records, metrics=metrics)), ensure_ascii=False)
        self.assertNotIn(secret_value, blob)
        self.assertNotIn(SECRET, blob)
        self.assertNotIn("12345", blob)


class PartitionValidationTest(unittest.TestCase):
    def test_missing_empty_or_wrong_type(self):
        records = [{"g": "a"}]
        for raw in (None, [], "x", {}, 1):
            with self.subTest(raw=raw):
                with self.assertRaises(InvalidPartition):
                    run(body(records, partitions=raw))

    def test_key_width_must_match_group_by(self):
        for partitions in ([["a", "b"]], [[]], [["a"], []]):
            with self.subTest(partitions=partitions):
                with self.assertRaises(InvalidPartition):
                    run(body([{"g": "a"}], partitions=partitions))

    def test_key_elements_must_be_scalars(self):
        for key in ([[{"x": 1}]], [[["a"]]], [[float("nan")]]):
            with self.subTest(key=key):
                with self.assertRaises(InvalidPartition):
                    run(body([{"g": "a"}], partitions=key))

    def test_duplicate_keys_rejected_with_json_equality(self):
        for partitions in ([["a"], ["a"]], [[1], [1.0]], [[None], [None]], [[True], [True]]):
            with self.subTest(partitions=partitions):
                with self.assertRaises(InvalidPartition):
                    run(body([{"g": "a"}], partitions=partitions))

    def test_distinct_types_are_not_duplicates(self):
        run(body([{"g": "a"}], partitions=[[0], [False], [None], ["0"]]))


class GroupByValidationTest(unittest.TestCase):
    def test_invalid_group_by(self):
        records = [{"g": "a"}]
        for raw in (None, "x", ["/g", "/g"], ["/missing"], [""], [1]):
            with self.subTest(raw=raw):
                with self.assertRaises(InvalidGroupBy):
                    run(body(records, group_by=raw))

    def test_group_value_must_be_scalar_on_every_record(self):
        with self.assertRaises(InvalidGroupBy):
            run(body([{"g": {"x": 1}}]))
        with self.assertRaises(InvalidGroupBy):
            run(body([{"g": "a"}, {"h": "b"}]))


class MetricValidationTest(unittest.TestCase):
    def test_metrics_must_be_non_empty_array_of_objects(self):
        for raw in (None, [], "x", [1], [None]):
            with self.subTest(raw=raw):
                with self.assertRaises(InvalidMetric):
                    run(body([{"g": "a"}], metrics=raw))

    def test_names_unique_and_operations_known(self):
        with self.assertRaises(InvalidMetric):
            run(body([{"g": "a"}], metrics=[COUNT, COUNT]))
        with self.assertRaises(InvalidMetric):
            run(body([{"g": "a"}], metrics=[{"name": "m", "operation": "average", "epsilon": 1}]))

    def test_count_must_not_carry_field_or_bounds(self):
        for extra in ({"field": "/v"}, {"lower": 0}, {"upper": 1}):
            with self.subTest(extra=extra):
                with self.assertRaises(InvalidMetric):
                    run(body([{"g": "a"}], metrics=[{**COUNT, **extra}]))

    def test_sum_requires_field_and_bounds(self):
        base = {"name": "s", "operation": "sum", "epsilon": 1}
        for extra in ({}, {"field": "/v"}, {"field": "/v", "lower": 0},
                      {"field": "/v", "lower": 1, "upper": 1},
                      {"field": "/v", "lower": 2, "upper": 1},
                      {"field": "/v", "lower": True, "upper": 1},
                      {"field": "/v", "lower": 0, "upper": "x"}):
            with self.subTest(extra=extra):
                with self.assertRaises(InvalidMetric):
                    run(body([{"g": "a", "v": 1}], metrics=[{**base, **extra}]))

    def test_sum_field_must_be_finite_number_on_every_record(self):
        metric = {"name": "s", "operation": "sum", "field": "/v",
                  "lower": 0, "upper": 1, "epsilon": 1}
        for records in ([{"g": "a", "v": "x"}], [{"g": "a", "v": True}],
                        [{"g": "a", "v": 1}, {"g": "a"}]):
            with self.subTest(records=records):
                with self.assertRaises(InvalidMetric):
                    run(body(records, metrics=[metric]))


class PrivacyBudgetValidationTest(unittest.TestCase):
    def test_epsilon_bounds(self):
        for epsilon in (None, 0, -1, 10.5, "1", True, float("nan")):
            with self.subTest(epsilon=epsilon):
                with self.assertRaises(InvalidPrivacyBudget):
                    run(body([{"g": "a"}],
                             metrics=[{"name": "n", "operation": "count", "epsilon": epsilon}]))

    def test_epsilon_boundary_ten_accepted(self):
        run(body([{"g": "a"}], metrics=[{"name": "n", "operation": "count", "epsilon": 10}]))

    def test_budget_shape(self):
        for budget in (None, [], {"limit": 1}, {"spent": 0},
                       {"limit": -1, "spent": 0}, {"limit": 1, "spent": -0.5},
                       {"limit": "1", "spent": 0}, {"limit": 1, "spent": False}):
            with self.subTest(budget=budget):
                with self.assertRaises(InvalidPrivacyBudget):
                    run(body([{"g": "a"}], budget=budget))

    def test_insufficient_balance_not_published(self):
        with self.assertRaises(InvalidPrivacyBudget):
            run(body([{"g": "a"}], budget={"limit": 0.5, "spent": 0}))
        with self.assertRaises(InvalidPrivacyBudget):
            run(body([{"g": "a"}], budget={"limit": 2, "spent": 1.5}))


class NoiseConfigValidationTest(unittest.TestCase):
    def test_release_id_must_be_non_empty_string(self):
        for release_id in (None, "", 1, ["x"]):
            with self.subTest(release_id=release_id):
                with self.assertRaises(InvalidNoiseConfig):
                    run(body([{"g": "a"}], release_id=release_id))

    def test_noise_secret_must_be_unpadded_base64url_32_bytes(self):
        short = base64.urlsafe_b64encode(b"s" * 31).rstrip(b"=").decode("ascii")
        for secret in (None, "", 1, "not base64!", short, SECRET + "="):
            with self.subTest(secret=secret):
                with self.assertRaises(InvalidNoiseConfig):
                    run(body([{"g": "a"}], noise_secret=secret))


class RequestShapeValidationTest(unittest.TestCase):
    def test_invalid_request(self):
        for payload in (None, [], "x", {}, {"records": []}, {"records": [1]}):
            with self.subTest(payload=payload):
                with self.assertRaises(InvalidRequest):
                    run(payload)

    def test_validation_order(self):
        # records before group_by, group_by before partitions, and so on.
        with self.assertRaises(InvalidRequest):
            run({"records": [], "group_by": ["bad"]})
        with self.assertRaises(InvalidGroupBy):
            run(body([{"g": "a"}], group_by=["bad"], partitions="bad"))
        with self.assertRaises(InvalidPartition):
            run(body([{"g": "a"}], partitions="bad", metrics="bad"))
        with self.assertRaises(InvalidMetric):
            run(body([{"g": "a"}], metrics="bad", budget="bad"))
        with self.assertRaises(InvalidPrivacyBudget):
            run(body([{"g": "a"}], budget="bad", release_id=""))


class DifferentialHttpTest(unittest.TestCase):
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
        return self.request("POST", "/v1/query/differential-aggregate", body=raw,
                            content_type=content_type)

    def test_happy_path(self):
        status, payload, _ = self.post(body([{"g": "a"}, {"g": "b"}, {"g": "c"}]))
        self.assertEqual(status, 200)
        self.assertEqual(set(payload), {"partitions", "consumed", "spent", "remaining"})
        self.assertNotIn("results", payload)
        self.assertEqual([p["key"] for p in payload["partitions"]], [["a"], ["b"]])

    def test_method_not_allowed(self):
        for method in ("GET", "PUT", "DELETE", "PATCH"):
            with self.subTest(method=method):
                status, payload, allow = self.request(method, "/v1/query/differential-aggregate")
                self.assertEqual(status, 405)
                self.assertEqual(payload["error"]["code"], "method_not_allowed")
                self.assertEqual(allow, "POST")

    def test_unknown_path_still_404(self):
        status, payload, _ = self.request("POST", "/v1/query/differential")
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

    def test_error_codes(self):
        cases = [
            ("invalid_request", {"records": []}),
            ("invalid_group_by", body([{"g": "a"}], group_by=["bad"])),
            ("invalid_partition", body([{"g": "a"}], partitions=[])),
            ("invalid_metric", body([{"g": "a"}], metrics=[])),
            ("invalid_privacy_budget", body([{"g": "a"}], budget={"limit": 0, "spent": 1})),
            ("invalid_privacy_budget", body([{"g": "a"}],
                                            metrics=[{"name": "n", "operation": "count",
                                                      "epsilon": 0}])),
            ("invalid_noise_config", body([{"g": "a"}], noise_secret="short")),
        ]
        for code, payload in cases:
            with self.subTest(code=code):
                status, parsed, _ = self.post(payload)
                self.assertEqual(status, 422)
                self.assertEqual(parsed["error"]["code"], code)

    def test_no_partial_results_on_failure(self):
        status, payload, _ = self.post(body([{"g": "a"}], budget={"limit": 0, "spent": 0}))
        self.assertEqual(status, 422)
        self.assertNotIn("partitions", payload)
        self.assertNotIn("consumed", payload)

    def test_error_does_not_echo_records_or_secret(self):
        secret_note = "rare-disease-label"
        payload = body([{"g": "a", "note": secret_note}], noise_secret="short")
        status, parsed, _ = self.post(payload)
        self.assertEqual(status, 422)
        blob = json.dumps(parsed, ensure_ascii=False)
        self.assertNotIn(secret_note, blob)
        self.assertNotIn(SECRET, blob)


if __name__ == "__main__":
    unittest.main()
