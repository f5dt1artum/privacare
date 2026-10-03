import base64
import copy
import http.client
import json
import threading
import unittest
from contextlib import contextmanager
from decimal import Decimal
from http.server import ThreadingHTTPServer

from privacare.classifier import InvalidRequest
from privacare.aggregate import InvalidGroupBy, InvalidMetric
from privacare import differential as differential_module
from privacare.differential import (
    InvalidNoiseConfig,
    InvalidPartition,
    InvalidPrivacyBudget,
    differential_aggregate_request,
)
from privacare.server import Handler
from privacare.service import Service

SECRET_BYTES = b"0123456789abcdef0123456789abcdef"
SECRET = base64.urlsafe_b64encode(SECRET_BYTES).rstrip(b"=").decode()


@contextmanager
def patch_draw(value):
    """Force the standard-Laplace draw to a fixed value for deterministic checks."""
    original = differential_module._laplace_draw
    differential_module._laplace_draw = lambda secret, release_id, signature, name: value
    try:
        yield
    finally:
        differential_module._laplace_draw = original



def run(payload):
    return Service().differential_aggregate(payload)


def count_metric(name="n", epsilon=1.0):
    return {"name": name, "type": "count", "epsilon": epsilon}


def body(
    records,
    partitions,
    metrics=None,
    group_by=None,
    limit=10.0,
    spent=0.0,
    release_id="release-1",
    noise_secret=SECRET,
):
    payload = {
        "records": records,
        "partitions": partitions,
        "metrics": metrics if metrics is not None else [count_metric()],
        "budget": {"limit": limit, "spent": spent},
        "release_id": release_id,
        "noise_secret": noise_secret,
    }
    if group_by is not None:
        payload["group_by"] = group_by
    return payload


class HappyPathTest(unittest.TestCase):
    def test_all_public_partitions_returned_in_order_including_empty(self):
        records = [
            {"city": "BJ"}, {"city": "BJ"}, {"city": "SH"}, {"city": "UNKNOWN"},
        ]
        response = run(body(records, [["BJ"], ["SH"], ["GZ"]], group_by=["/city"]))
        self.assertEqual([p["key"] for p in response["partitions"]], [["BJ"], ["SH"], ["GZ"]])
        self.assertEqual(set(response), {"partitions", "budget"})
        for partition in response["partitions"]:
            self.assertEqual(set(partition), {"key", "metrics"})

    def test_response_shape_and_budget_accounting(self):
        response = run(
            body(
                [{"g": "a", "v": 1.5}, {"g": "a", "v": 2.5}],
                [["a"], ["b"]],
                metrics=[
                    count_metric("n", 1.0),
                    {"name": "s", "type": "sum", "field": "/v", "lower": 0, "upper": 10, "epsilon": 2.0},
                ],
                group_by=["/g"],
                limit=10,
                spent=4,
            )
        )
        self.assertEqual(
            response["budget"],
            {"consumed": 3.0, "spent": 7.0, "remaining": 3.0},
        )
        for partition in response["partitions"]:
            self.assertEqual(set(partition["metrics"]), {"n", "s"})

    def test_consumed_is_sum_of_epsilons_independent_of_partition_count(self):
        records = [{"g": k} for k in ("a", "b", "c")]
        one = run(body(records, [["a"]], group_by=["/g"]))
        many = run(body(records, [["a"], ["b"], ["c"], ["d"]], group_by=["/g"]))
        self.assertEqual(one["budget"]["consumed"], many["budget"]["consumed"])

    def test_global_grouping_with_empty_or_omitted_group_by(self):
        records = [{"v": 1}, {"v": 2}]
        explicit = run(body(records, [[]], group_by=[]))
        omitted = run(body(records, [[]]))
        self.assertEqual(explicit["partitions"][0]["key"], [])
        self.assertEqual(omitted["partitions"][0]["key"], [])

    def test_numeric_equality_and_typed_keys(self):
        records = [{"g": 1, "v": 1}, {"g": 1.0, "v": 2}]
        response = run(
            body(
                records,
                [[1.0], [True], [None], ["1"], [False], [0]],
                metrics=[
                    count_metric("n"),
                    {"name": "s", "type": "sum", "field": "/v", "lower": 0, "upper": 5, "epsilon": 1.0},
                ],
                group_by=["/g"],
            )
        )
        keys = [tuple(json.dumps(p["key"])) for p in response["partitions"]]
        self.assertEqual(len(keys), len(set(keys)))
        self.assertEqual(
            [p["key"] for p in response["partitions"]],
            [[1.0], [True], [None], ["1"], [False], [0]],
        )
        # Both numeric records fall in the single 1/1.0 partition.
        self.assertGreaterEqual(response["partitions"][0]["metrics"]["n"], 1.0)

    def test_sum_is_clipped_to_bounds_per_record(self):
        records = [{"g": "a", "v": 20}, {"g": "a", "v": -20}]
        payload = body(
            records,
            [["a"], ["b"]],
            metrics=[{"name": "s", "type": "sum", "field": "/v", "lower": 0, "upper": 10, "epsilon": 1.0}],
            group_by=["/g"],
        )
        # Pin the noise draw to zero so the released value is exactly the
        # clipped true sum: 20 -> 10, -20 -> 0, hence 10 for the group.
        with patch_draw(Decimal(0)):
            response = run(payload)
        self.assertEqual(response["partitions"][0]["metrics"]["s"], 10.0)
        # Empty partition's true sum is zero.
        self.assertEqual(response["partitions"][1]["metrics"]["s"], 0.0)

    def test_sensitivity_scales_match_spec(self):
        records = [{"g": "a", "v": 2}, {"g": "a", "v": 3}]
        payload = body(
            records,
            [["a"]],
            metrics=[
                count_metric("n", 2.0),
                {"name": "s", "type": "sum", "field": "/v", "lower": 0, "upper": 10, "epsilon": 5.0},
            ],
            group_by=["/g"],
        )
        # A unit standard-Laplace draw adds scale = sensitivity/epsilon:
        # count 1/2 = 0.5 (true 2 -> 2.5), sum (10-0)/5 = 2 (true 5 -> 7).
        with patch_draw(Decimal(1)):
            response = run(payload)
        metrics = response["partitions"][0]["metrics"]
        self.assertEqual(metrics["n"], 2.5)
        self.assertEqual(metrics["s"], 7.0)

    def test_negative_count_draw_is_floored_to_zero(self):
        payload = body([{"g": "a"}], [["b"]], group_by=["/g"])
        with patch_draw(Decimal(-5)):
            response = run(payload)
        self.assertEqual(response["partitions"][0]["metrics"]["n"], 0.0)


class DeterminismTest(unittest.TestCase):
    def payload(self, release_id="r1", secret=SECRET):
        return body(
            [{"g": "a", "v": 1}, {"g": "b", "v": 2}],
            [["a"], ["b"], ["c"]],
            metrics=[
                count_metric("n", 0.5),
                {"name": "s", "type": "sum", "field": "/v", "lower": 0, "upper": 4, "epsilon": 0.7},
            ],
            group_by=["/g"],
            release_id=release_id,
            noise_secret=secret,
        )

    def test_retry_same_release_is_identical(self):
        payload = self.payload()
        first = run(payload)
        second = run(copy.deepcopy(payload))
        self.assertEqual(first, second)

    def test_changing_release_id_changes_noise(self):
        baseline = run(self.payload("r1"))
        other = run(self.payload("r2"))
        self.assertNotEqual(
            [p["metrics"] for p in baseline["partitions"]],
            [p["metrics"] for p in other["partitions"]],
        )

    def test_changing_secret_changes_noise(self):
        other_secret = base64.urlsafe_b64encode(b"x" * 32).rstrip(b"=").decode()
        baseline = run(self.payload(secret=SECRET))
        other = run(self.payload(secret=other_secret))
        self.assertNotEqual(
            [p["metrics"] for p in baseline["partitions"]],
            [p["metrics"] for p in other["partitions"]],
        )

    def test_noise_is_independent_across_partitions_and_metrics(self):
        response = run(self.payload())
        draws = [
            (tuple(p["key"]), name, value)
            for p in response["partitions"]
            for name, value in p["metrics"].items()
        ]
        # With independent draws, six (partition, metric) values cannot all
        # coincide; sanity-check that keys/metrics produce distinct entries.
        values = [value for _k, _n, value in draws]
        self.assertGreater(len(set(round(v, 3) for v in values)), 1)

    def test_input_not_mutated(self):
        payload = self.payload()
        snapshot = copy.deepcopy(payload)
        run(payload)
        self.assertEqual(payload, snapshot)


class RoundingTest(unittest.TestCase):
    def test_budget_and_metrics_round_to_six_places(self):
        response = run(
            body(
                [{"g": "a"}],
                [["a"]],
                metrics=[count_metric("n", 0.123456789)],
                group_by=["/g"],
                limit=1.0101015,
                spent=0.0,
            )
        )
        for key, value in response["budget"].items():
            with self.subTest(key=key):
                self.assertEqual(round(value, 6), value)


class GroupByValidationTest(unittest.TestCase):
    def test_bad_group_by(self):
        records = [{"a": 1}]
        for raw in (1, "x", {}, [1], ["/a", "/a"], ["/b"], ["/a/x"], ["bad"]):
            with self.subTest(raw=raw):
                with self.assertRaises(InvalidGroupBy):
                    run(body(records, [[1]], group_by=raw))

    def test_group_by_resolving_to_container_invalid(self):
        with self.assertRaises(InvalidGroupBy):
            run(body([{"a": {"b": 1}}], [[{"b": 1}]], group_by=["/a"]))
        with self.assertRaises(InvalidGroupBy):
            run(body([{"a": [1]}], [[[1]]], group_by=["/a"]))


class PartitionValidationTest(unittest.TestCase):
    def _records(self):
        return [{"g": "a"}]

    def test_partitions_must_be_non_empty_array(self):
        for raw in (None, [], "x", 1, {}):
            with self.subTest(raw=raw):
                payload = body(self._records(), [["a"]], group_by=["/g"])
                payload["partitions"] = raw
                with self.assertRaises(InvalidPartition):
                    run(payload)

    def test_keys_must_be_arrays_matching_group_by_width(self):
        for raw in (["a"], [[]], [["a", "b"]]):
            with self.subTest(raw=raw):
                with self.assertRaises(InvalidPartition):
                    run(body(self._records(), raw, group_by=["/g"]))

    def test_global_partition_key_must_be_empty(self):
        # No group_by -> only [] is a legal key.
        with self.assertRaises(InvalidPartition):
            run(body([{"v": 1}], [["a"]]))
        run(body([{"v": 1}], [[]]))

    def test_scalar_elements_only(self):
        for raw in ([[["x"]]], [[{"x": 1}]], [[float("nan")]]):
            with self.subTest(raw=raw):
                payload = body(self._records(), raw, group_by=["/g"])
                # NaN survives JSON in-process but container keys must fail.
                if isinstance(raw[0][0], float):
                    with self.assertRaises((InvalidPartition, InvalidGroupBy)):
                        run(payload)
                else:
                    with self.assertRaises(InvalidPartition):
                        run(payload)

    def test_duplicate_keys_rejected_with_numeric_equality(self):
        with self.assertRaises(InvalidPartition):
            run(body(self._records(), [["a"], ["a"]], group_by=["/g"]))
        with self.assertRaises(InvalidPartition):
            run(body([{"g": 1}], [[1], [1.0]], group_by=["/g"]))

    def test_typed_duplicates_distinct(self):
        # null / false / 0 are different keys and must be accepted.
        response = run(
            body([{"g": None}], [[None], [False], [0]], group_by=["/g"])
        )
        self.assertEqual(len(response["partitions"]), 3)


class MetricValidationTest(unittest.TestCase):
    def sum_metric(self, **overrides):
        metric = {"name": "s", "type": "sum", "field": "/v", "lower": 0, "upper": 10, "epsilon": 1.0}
        metric.update(overrides)
        return metric

    def test_metrics_non_empty_array_of_objects_with_unique_names(self):
        records = [{"g": "a", "v": 1}]
        for metrics in (None, [], "x", [1], [{"name": "n", "type": "weird", "epsilon": 1}]):
            with self.subTest(metrics=metrics):
                payload = body(records, [["a"]], group_by=["/g"])
                payload["metrics"] = metrics
                with self.assertRaises(InvalidMetric):
                    run(payload)
        with self.assertRaises(InvalidMetric):
            run(body(
                records, [["a"]],
                metrics=[count_metric("dup"), count_metric("dup")],
                group_by=["/g"],
            ))

    def test_type_must_be_count_or_sum(self):
        with self.assertRaises(InvalidMetric):
            run(body([{"g": "a"}], [["a"]], metrics=[{"name": "m", "epsilon": 1}], group_by=["/g"]))

    def test_count_must_not_carry_field_or_bounds(self):
        for metric in (
            {"name": "m", "type": "count", "epsilon": 1, "field": "/v"},
            {"name": "m", "type": "count", "epsilon": 1, "lower": 0},
            {"name": "m", "type": "count", "epsilon": 1, "upper": 1},
        ):
            with self.subTest(metric=metric):
                with self.assertRaises(InvalidMetric):
                    run(body([{"g": "a", "v": 1}], [["a"]], metrics=[metric], group_by=["/g"]))

    def test_sum_requires_field_and_valid_pointer(self):
        for field in (None, "", "a", "/", "/a~2", 1):
            with self.subTest(field=field):
                with self.assertRaises(InvalidMetric):
                    run(body(
                        [{"g": "a", "v": 1}], [["a"]],
                        metrics=[self.sum_metric(field=field)], group_by=["/g"],
                    ))

    def test_sum_bounds_must_be_finite_and_ordered(self):
        records = [{"g": "a", "v": 1}]
        for lower, upper in ((None, 1), (0, None), ("0", 1), (0, True), (1, 1), (5, 2), (float("nan"), 1)):
            with self.subTest(lower=lower, upper=upper):
                with self.assertRaises(InvalidMetric):
                    run(body(
                        records, [["a"]],
                        metrics=[self.sum_metric(lower=lower, upper=upper)], group_by=["/g"],
                    ))

    def test_sum_field_must_be_finite_number_on_every_record(self):
        for value in (True, "1", None, [1], float("inf")):
            with self.subTest(value=value):
                with self.assertRaises(InvalidMetric):
                    run(body(
                        [{"g": "a", "v": value}], [["a"]],
                        metrics=[self.sum_metric()], group_by=["/g"],
                    ))
        with self.assertRaises(InvalidMetric):
            run(body(
                [{"g": "a", "v": 1}, {"g": "a", "w": 2}], [["a"]],
                metrics=[self.sum_metric()], group_by=["/g"],
            ))


class BudgetValidationTest(unittest.TestCase):
    def _body(self, **budget):
        payload = body([{"g": "a"}], [["a"]], group_by=["/g"])
        payload["budget"] = budget or None
        return payload

    def test_budget_shape(self):
        for budget in (None, [], "x", {}, {"limit": 1}, {"spent": 0},
                       {"limit": "1", "spent": 0}, {"limit": True, "spent": 0}):
            with self.subTest(budget=budget):
                payload = body([{"g": "a"}], [["a"]], group_by=["/g"])
                payload["budget"] = budget
                with self.assertRaises(InvalidPrivacyBudget):
                    run(payload)

    def test_negative_limit_or_spent_rejected(self):
        with self.assertRaises(InvalidPrivacyBudget):
            run(body([{"g": "a"}], [["a"]], group_by=["/g"], limit=-1, spent=0))
        with self.assertRaises(InvalidPrivacyBudget):
            run(body([{"g": "a"}], [["a"]], group_by=["/g"], limit=1, spent=-0.1))

    def test_epsilon_bounds_and_type(self):
        for epsilon in (0, -1, 10.0001, 11, "1", True, None, float("nan")):
            with self.subTest(epsilon=epsilon):
                with self.assertRaises(InvalidPrivacyBudget):
                    run(body(
                        [{"g": "a"}], [["a"]],
                        metrics=[count_metric(epsilon=epsilon)], group_by=["/g"],
                    ))

    def test_epsilon_boundaries_accepted(self):
        run(body([{"g": "a"}], [["a"]], metrics=[count_metric(epsilon=10.0)], group_by=["/g"]))

    def test_insufficient_balance_blocks_release(self):
        # consumed = 1 (count) + 2 (sum) = 3; spent 8 with limit 10 -> 2 < 3.
        with self.assertRaises(InvalidPrivacyBudget):
            run(body(
                [{"g": "a", "v": 1}], [["a"]],
                metrics=[count_metric("n", 1.0),
                         {"name": "s", "type": "sum", "field": "/v", "lower": 0, "upper": 1, "epsilon": 2.0}],
                group_by=["/g"], limit=10, spent=8,
            ))

    def test_exact_balance_accepted(self):
        response = run(body([{"g": "a"}], [["a"]], group_by=["/g"], limit=1, spent=0))
        self.assertEqual(response["budget"], {"consumed": 1.0, "spent": 1.0, "remaining": 0.0})


class NoiseConfigValidationTest(unittest.TestCase):
    def test_release_id_must_be_non_empty_string(self):
        for release_id in (None, "", 1, ["x"]):
            with self.subTest(release_id=release_id):
                with self.assertRaises(InvalidNoiseConfig):
                    run(body([{"g": "a"}], [["a"]], group_by=["/g"], release_id=release_id))

    def test_secret_must_be_unpadded_base64url_of_at_least_32_bytes(self):
        short = base64.urlsafe_b64encode(b"short").rstrip(b"=").decode()
        padded = base64.urlsafe_b64encode(SECRET_BYTES).decode()  # includes '='
        for secret in (None, "", 123, "!!!", short, padded, "A" * 42 + "="):
            with self.subTest(secret=secret):
                with self.assertRaises(InvalidNoiseConfig):
                    run(body([{"g": "a"}], [["a"]], group_by=["/g"], noise_secret=secret))

    def test_secret_longer_than_32_bytes_accepted(self):
        long_secret = base64.urlsafe_b64encode(b"k" * 40).rstrip(b"=").decode()
        run(body([{"g": "a"}], [["a"]], group_by=["/g"], noise_secret=long_secret))


class RequestShapeTest(unittest.TestCase):
    def test_invalid_request(self):
        good = body([{"g": "a"}], [["a"]], group_by=["/g"])
        for payload in (
            None, [], "x", {},
            {**good, "records": None},
            {**good, "records": []},
            {**good, "records": [1]},
        ):
            with self.subTest(payload=payload):
                with self.assertRaises(InvalidRequest):
                    run(payload)

    def test_no_partial_results_and_no_record_or_secret_echo(self):
        secret_value = "supersecret-bytes-aaaaaaa"
        secret = base64.urlsafe_b64encode(secret_value.encode().ljust(32, b"0")).rstrip(b"=").decode()
        # Trigger several distinct failure kinds; none of their messages may
        # echo record values or the secret material.
        bad_payloads = [
            body([{"g": "RARE-CITY", "v": 1}], "not-a-key", group_by=["/g"], noise_secret=secret),
            body([{"g": "RARE-CITY"}], [["a"], ["a"]], group_by=["/g"], noise_secret=secret),
            body([{"g": "RARE-CITY", "v": "x"}], [["a"]],
                 metrics=[{"name": "s", "type": "sum", "field": "/v", "lower": 0, "upper": 1, "epsilon": 1}],
                 group_by=["/g"], noise_secret=secret),
        ]
        for payload in bad_payloads:
            with self.subTest(payload=payload):
                with self.assertRaises(ValueError) as ctx:
                    differential_aggregate_request(payload)
                message = str(ctx.exception)
                self.assertNotIn("RARE-CITY", message)
                self.assertNotIn(secret_value, message)


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
        return self.request("POST", "/v1/query/differential-aggregate", body=raw, content_type=content_type)

    def good_payload(self):
        return body(
            [{"city": "BJ"}, {"city": "SH"}],
            [["BJ"], ["SH"], ["GZ"]],
            group_by=["/city"],
        )

    def test_happy_path(self):
        status, payload, _ = self.post(self.good_payload())
        self.assertEqual(status, 200)
        self.assertEqual([p["key"] for p in payload["partitions"]], [["BJ"], ["SH"], ["GZ"]])
        self.assertEqual(set(payload["budget"]), {"consumed", "spent", "remaining"})
        self.assertNotIn("results", payload)

    def test_method_not_allowed(self):
        for method in ("GET", "PUT", "DELETE", "PATCH"):
            with self.subTest(method=method):
                status, payload, allow = self.request(method, "/v1/query/differential-aggregate")
                self.assertEqual(status, 405)
                self.assertEqual(payload["error"]["code"], "method_not_allowed")
                self.assertEqual(allow, "POST")

    def test_unknown_path_404(self):
        status, payload, _ = self.request("POST", "/v1/query/nope")
        self.assertEqual(status, 404)
        self.assertEqual(payload["error"]["code"], "not_found")

    def test_unsupported_media_type_and_invalid_json(self):
        status, payload, _ = self.post("{}", content_type="text/plain")
        self.assertEqual(status, 415)
        self.assertEqual(payload["error"]["code"], "unsupported_media_type")
        status, payload, _ = self.post("{not json")
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"]["code"], "invalid_json")

    def test_error_codes(self):
        cases = [
            ("invalid_request", {**self.good_payload(), "records": []}),
            ("invalid_group_by", {**self.good_payload(), "group_by": ["/missing"]}),
            ("invalid_partition", {**self.good_payload(), "partitions": [["BJ"], ["BJ"]]}),
            (
                "invalid_metric",
                {**self.good_payload(),
                 "metrics": [{"name": "s", "type": "sum", "field": "/nope", "lower": 0, "upper": 1, "epsilon": 1}]},
            ),
            (
                "invalid_privacy_budget",
                {**self.good_payload(),
                 "metrics": [count_metric("n", 10.0)], "budget": {"limit": 1, "spent": 0}},
            ),
            ("invalid_noise_config", {**self.good_payload(), "release_id": ""}),
        ]
        for code, payload in cases:
            with self.subTest(code=code):
                status, parsed, _ = self.post(payload)
                self.assertEqual(status, 422)
                self.assertEqual(parsed["error"]["code"], code)
                self.assertNotIn("partitions", parsed)

    def test_error_body_does_not_echo_records_or_secret(self):
        payload = self.good_payload()
        payload["noise_secret"] = "not-base64!!"
        payload["records"] = [{"city": "SECRET-CITY-123"}]
        status, parsed, _ = self.post(payload)
        self.assertEqual(status, 422)
        blob = json.dumps(parsed)
        self.assertNotIn("SECRET-CITY-123", blob)


if __name__ == "__main__":
    unittest.main()
