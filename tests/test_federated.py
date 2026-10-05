import copy
import http.client
import json
import threading
import unittest
from http.server import ThreadingHTTPServer

from privacare.classifier import InvalidRequest
from privacare.federated import (
    InsufficientParticipants,
    InvalidFederatedConfig,
    InvalidUpdate,
    federated_aggregate_request,
)
from privacare.server import Handler
from privacare.service import Service


def run(payload):
    return Service().federated_aggregate(payload)


def update(participant_id, values, sample_count=1):
    return {"participant_id": participant_id, "sample_count": sample_count, "values": values}


def body(updates, **overrides):
    payload = {
        "round_id": "round-1",
        "minimum_participants": 2,
        "max_l2_norm": 10.0,
        "updates": updates,
    }
    payload.update(overrides)
    return payload


class HappyPathTest(unittest.TestCase):
    def test_basic_weighted_average(self):
        response = run(
            body(
                [
                    update("a", [1.0, 2.0], sample_count=1),
                    update("b", [4.0, 6.0], sample_count=3),
                ]
            )
        )
        self.assertEqual(
            set(response),
            {
                "round_id",
                "participant_count",
                "total_sample_count",
                "dimension",
                "aggregate",
                "clipped_participants",
            },
        )
        self.assertEqual(response["round_id"], "round-1")
        self.assertEqual(response["participant_count"], 2)
        self.assertEqual(response["total_sample_count"], 4)
        self.assertEqual(response["dimension"], 2)
        self.assertEqual(response["aggregate"], [3.25, 5.0])
        self.assertEqual(response["clipped_participants"], [])

    def test_clipped_vector_is_scaled_whole(self):
        # norm of [6, 8] is 10, clip bound 5 => scale 0.5 => [3, 4];
        # weighted with the untouched [3, 4] (norm exactly 5, not clipped).
        response = run(
            body(
                [
                    update("b", [3.0, 4.0], sample_count=2),
                    update("a", [6.0, 8.0], sample_count=1),
                ],
                max_l2_norm=5.0,
            )
        )
        self.assertEqual(response["aggregate"], [3.0, 4.0])
        self.assertEqual(response["clipped_participants"], ["a"])

    def test_vector_at_bound_is_not_clipped(self):
        response = run(
            body(
                [
                    update("a", [3.0, 4.0], sample_count=1),
                    update("b", [0.0, 5.0], sample_count=1),
                ],
                max_l2_norm=5.0,
            )
        )
        self.assertEqual(response["clipped_participants"], [])
        self.assertEqual(response["aggregate"], [1.5, 4.5])

    def test_zero_vector_is_unchanged_and_not_listed(self):
        # [2, 4] has norm sqrt(20) and clips to bound 1; the zero vector
        # contributes zero weight*value and is never listed as clipped.
        response = run(
            body(
                [
                    update("a", [0.0, 0.0], sample_count=2),
                    update("b", [2.0, 4.0], sample_count=2),
                ],
                max_l2_norm=1.0,
            )
        )
        self.assertEqual(response["clipped_participants"], ["b"])
        self.assertEqual(response["aggregate"], [0.223607, 0.447214])

    def test_clipped_list_sorted_regardless_of_input_order(self):
        updates = [
            update("zeta", [100.0], sample_count=1),
            update("alpha", [100.0], sample_count=1),
            update("mid", [100.0], sample_count=1),
            update("keep", [0.0], sample_count=1),
        ]
        response = run(body(updates, max_l2_norm=1.0, minimum_participants=2))
        self.assertEqual(response["clipped_participants"], ["alpha", "mid", "zeta"])

    def test_order_does_not_change_results(self):
        updates = [
            update("c", [3.0, -7.0, 0.25], sample_count=5),
            update("a", [0.0, 0.0, 0.0], sample_count=2),
            update("b", [6.0, 8.0, 1.5], sample_count=11),
        ]
        first = run(body(updates, max_l2_norm=5.0))
        for reordered in (list(reversed(updates)), [updates[1], updates[2], updates[0]]):
            self.assertEqual(run(body(reordered, max_l2_norm=5.0)), first)

    def test_integer_values_and_counts(self):
        response = run(
            body(
                [
                    update("a", [1, 3], sample_count=1),
                    update("b", [3, 5], sample_count=3),
                ]
            )
        )
        self.assertEqual(response["aggregate"], [2.5, 4.5])
        self.assertEqual(response["total_sample_count"], 4)

    def test_single_dimension_and_max_dimension_accepted(self):
        response = run(body([update("a", [7.0]), update("b", [3.0])]))
        self.assertEqual(response["dimension"], 1)
        self.assertEqual(response["aggregate"], [5.0])

        wide_a = [0.0] * 4096
        wide_b = [1.0] * 4096  # norm 64, below the bound, so no clipping
        response = run(
            body(
                [
                    update("a", wide_a, sample_count=1),
                    update("b", wide_b, sample_count=1),
                ],
                max_l2_norm=100.0,
            )
        )
        self.assertEqual(response["dimension"], 4096)
        self.assertEqual(response["aggregate"], [0.5] * 4096)

    def test_threshold_exactly_met_publishes(self):
        response = run(
            body(
                [update("a", [1.0]), update("b", [2.0]), update("c", [3.0])],
                minimum_participants=3,
            )
        )
        self.assertEqual(response["participant_count"], 3)
        self.assertEqual(response["aggregate"], [2.0])

    def test_rounding_is_decimal_half_up_six_places(self):
        # weights 1 and 1: mean 0.1234565 -> half up -> 0.123457
        response = run(
            body(
                [
                    update("a", [0.0], sample_count=1),
                    update("b", [0.246913], sample_count=1),
                ]
            )
        )
        self.assertEqual(response["aggregate"], [0.123457])

    def test_negative_zero_is_normalized_to_zero(self):
        response = run(
            body(
                [
                    update("a", [-0.0], sample_count=1),
                    update("b", [0.0], sample_count=1),
                ]
            )
        )
        self.assertEqual(response["aggregate"], [0.0])
        self.assertNotIn("-0.0", json.dumps(response["aggregate"]))

        # A tiny negative mean that rounds to zero must also serialize as 0.
        response = run(
            body(
                [
                    update("a", [-0.0000001], sample_count=1),
                    update("b", [0.0], sample_count=1),
                ],
                max_l2_norm=1.0,
            )
        )
        self.assertEqual(response["aggregate"], [0.0])
        self.assertEqual(json.dumps(response["aggregate"]), "[0.0]")

    def test_input_is_not_mutated(self):
        payload = body(
            [
                update("b", [3.0, 4.0], sample_count=2),
                update("a", [6.0, 8.0], sample_count=1),
            ],
            max_l2_norm=5.0,
        )
        snapshot = copy.deepcopy(payload)
        run(payload)
        self.assertEqual(payload, snapshot)


class RequestShapeValidationTest(unittest.TestCase):
    def test_root_must_be_object(self):
        for bad in ([], "x", 42, None):
            with self.subTest(bad=bad):
                with self.assertRaises(InvalidRequest):
                    federated_aggregate_request(bad)

    def test_updates_must_be_non_empty_array(self):
        base = {"round_id": "r", "minimum_participants": 2, "max_l2_norm": 1.0}
        for updates in (None, [], "x", {}, 1):
            with self.subTest(updates=updates):
                with self.assertRaises(InvalidRequest):
                    federated_aggregate_request({**base, "updates": updates})

    def test_update_entries_must_be_objects(self):
        with self.assertRaises(InvalidUpdate):
            run(body([update("a", [1.0]), "nope"]))


class ConfigValidationTest(unittest.TestCase):
    def test_round_id_must_be_non_empty_string(self):
        for bad in (None, "", 3, ["x"], True):
            with self.subTest(bad=bad):
                with self.assertRaises(InvalidFederatedConfig):
                    run(body([update("a", [1.0]), update("b", [1.0])], round_id=bad))

    def test_minimum_participants_must_be_int_2_to_100(self):
        updates = [update("a", [1.0]), update("b", [1.0])]
        for bad in (None, 1, 0, -2, 101, 2.0, "2", True, False):
            with self.subTest(bad=bad):
                with self.assertRaises(InvalidFederatedConfig):
                    run(body(updates, minimum_participants=bad))

    def test_max_l2_norm_must_be_positive_finite_number(self):
        updates = [update("a", [1.0]), update("b", [1.0])]
        for bad in (None, 0, -1.0, "5", True, float("inf"), float("-inf"), float("nan")):
            with self.subTest(bad=bad):
                with self.assertRaises(InvalidFederatedConfig):
                    run(body(updates, max_l2_norm=bad))


class UpdateValidationTest(unittest.TestCase):
    def test_missing_fields(self):
        good = {"participant_id": "a", "sample_count": 1, "values": [1.0]}
        for field in ("participant_id", "sample_count", "values"):
            broken = dict(good)
            del broken[field]
            with self.subTest(field=field):
                with self.assertRaises(InvalidUpdate):
                    run(body([broken, update("b", [1.0])]))

    def test_duplicate_participant_id(self):
        with self.assertRaises(InvalidUpdate):
            run(body([update("a", [1.0]), update("a", [2.0])]))

    def test_participant_id_must_be_non_empty_string(self):
        for bad in ("", 1, None, ["a"], True):
            with self.subTest(bad=bad):
                with self.assertRaises(InvalidUpdate):
                    run(body([update_obj(bad, [1.0]), update("b", [1.0])]))

    def test_sample_count_must_be_int_1_to_1000000(self):
        for bad in (0, -1, 1_000_001, 1.0, "1", True, False, None):
            with self.subTest(bad=bad):
                with self.assertRaises(InvalidUpdate):
                    run(body([update_obj("a", [1.0], bad), update("b", [1.0])]))

    def test_values_must_be_one_dimensional_non_empty_array(self):
        for bad in (None, [], {}, "[1]", 1, [[1.0]], ()):
            with self.subTest(bad=bad):
                with self.assertRaises(InvalidUpdate):
                    run(body([update_obj("a", bad), update("b", [1.0])]))

    def test_values_length_bounds(self):
        with self.assertRaises(InvalidUpdate):
            run(body([update("a", [0.0] * 4097), update("b", [0.0] * 4097)]))

    def test_elements_must_be_finite_numbers_booleans_rejected(self):
        for bad in (True, False, "1.0", None, [1.0], {}, float("inf"), float("nan")):
            with self.subTest(bad=bad):
                with self.assertRaises(InvalidUpdate):
                    run(body([update_obj("a", [bad]), update("b", [1.0])]))

    def test_dimensions_must_match(self):
        with self.assertRaises(InvalidUpdate):
            run(body([update("a", [1.0, 2.0]), update("b", [1.0, 2.0, 3.0])]))

    def test_invalid_update_takes_precedence_over_threshold(self):
        # Structural update problems are reported even when the count is short.
        with self.assertRaises(InvalidUpdate):
            run(
                body(
                    [update_obj("a", [True])],
                    minimum_participants=2,
                )
            )


class InsufficientParticipantsTest(unittest.TestCase):
    def test_below_threshold_rejected(self):
        with self.assertRaises(InsufficientParticipants):
            run(
                body(
                    [update("a", [1.0]), update("b", [2.0])],
                    minimum_participants=3,
                )
            )

    def test_no_partial_results_in_error(self):
        try:
            run(
                body(
                    [update("secret-participant", [12345.6789])],
                    minimum_participants=5,
                )
            )
        except InsufficientParticipants as exc:
            self.assertNotIn("secret-participant", str(exc))
            self.assertNotIn("12345.6789", str(exc))
        else:
            self.fail("expected InsufficientParticipants")

    def test_errors_do_not_echo_participant_data(self):
        secret_id = "pid-SECRET"
        secret_value = 98765.4321
        with self.assertRaises(InvalidUpdate) as ctx:
            run(body([update_obj(secret_id, [secret_value], "nope")]))
        self.assertNotIn(secret_id, str(ctx.exception))
        self.assertNotIn("98765", str(ctx.exception))


def update_obj(participant_id, values, sample_count=1):
    return {"participant_id": participant_id, "sample_count": sample_count, "values": values}


class FederatedHttpTest(unittest.TestCase):
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
        data = payload if isinstance(payload, (str, bytes)) else json.dumps(payload)
        return self.request("POST", "/v1/federated/aggregate", body=data, content_type=content_type)

    def test_happy_path(self):
        status, payload = self.post(
            body(
                [
                    update("b", [3.0, 4.0], sample_count=2),
                    update("a", [6.0, 8.0], sample_count=1),
                ],
                max_l2_norm=5.0,
            )
        )
        self.assertEqual(status, 200)
        self.assertEqual(
            payload,
            {
                "round_id": "round-1",
                "participant_count": 2,
                "total_sample_count": 3,
                "dimension": 2,
                "aggregate": [3.0, 4.0],
                "clipped_participants": ["a"],
            },
        )

    def test_unsupported_media_type(self):
        status, payload = self.post(body([update("a", [1.0]), update("b", [1.0])]),
                                    content_type="text/plain")
        self.assertEqual(status, 415)
        self.assertEqual(payload["error"]["code"], "unsupported_media_type")

    def test_invalid_json(self):
        status, payload = self.post("{not json")
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"]["code"], "invalid_json")

    def test_invalid_request(self):
        for bad in ([], {}, {"round_id": "r"}, '{"updates": []}'):
            with self.subTest(bad=bad):
                status, payload = self.post(bad)
                self.assertEqual(status, 422)
                self.assertEqual(payload["error"]["code"], "invalid_request")

    def test_invalid_federated_config(self):
        updates = [update("a", [1.0]), update("b", [1.0])]
        for bad in (
            body(updates, round_id=""),
            body(updates, minimum_participants=1),
            body(updates, minimum_participants=101),
            body(updates, max_l2_norm=0),
            body(updates, max_l2_norm="5"),
        ):
            with self.subTest(bad=bad):
                status, payload = self.post(bad)
                self.assertEqual(status, 422)
                self.assertEqual(payload["error"]["code"], "invalid_federated_config")

    def test_invalid_update(self):
        for bad in (
            body([{"sample_count": 1, "values": [1.0]}, update("b", [1.0])]),
            body([update("a", [1.0]), update("a", [2.0])]),
            body([update_obj("a", [1.0], 0), update("b", [1.0])]),
            body([update("a", [1.0]), update("b", [1.0, 2.0])]),
            body([update_obj("a", [True]), update("b", [1.0])]),
            body([update_obj("a", []), update("b", [1.0])]),
        ):
            with self.subTest(bad=bad):
                status, payload = self.post(bad)
                self.assertEqual(status, 422)
                self.assertEqual(payload["error"]["code"], "invalid_update")

    def test_insufficient_participants(self):
        status, payload = self.post(
            body([update("a", [1.0]), update("b", [1.0])], minimum_participants=3)
        )
        self.assertEqual(status, 422)
        self.assertEqual(payload["error"]["code"], "insufficient_participants")

    def test_method_not_allowed(self):
        for method in ("GET", "PUT", "DELETE", "PATCH"):
            with self.subTest(method=method):
                status, payload = self.request(method, "/v1/federated/aggregate")
                self.assertEqual(status, 405)
                self.assertEqual(payload["error"]["code"], "method_not_allowed")

    def test_unknown_path_404(self):
        status, payload = self.request("POST", "/v1/federated/nope", body="{}",
                                       content_type="application/json")
        self.assertEqual(status, 404)
        self.assertEqual(payload["error"]["code"], "not_found")

    def test_healthz_unchanged(self):
        status, payload = self.request("GET", "/healthz")
        self.assertEqual(status, 200)
        self.assertEqual(payload["status"], "ok")


if __name__ == "__main__":
    unittest.main()
