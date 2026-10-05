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


def body(updates, minimum_participants=2, round_id="round-1", max_l2_norm=10.0):
    return {
        "round_id": round_id,
        "minimum_participants": minimum_participants,
        "max_l2_norm": max_l2_norm,
        "updates": updates,
    }


def upd(participant_id, values, sample_count=10):
    return {"participant_id": participant_id, "sample_count": sample_count, "values": values}


class FederatedHappyPathTest(unittest.TestCase):
    def test_weighted_average_no_clipping(self):
        payload = body([upd("a", [1.0, 2.0], 10), upd("b", [3.0, 6.0], 30)])
        response = run(payload)
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
        self.assertEqual(response["total_sample_count"], 40)
        self.assertEqual(response["dimension"], 2)
        self.assertEqual(response["aggregate"], [2.5, 5.0])
        self.assertEqual(response["clipped_participants"], [])

    def test_clipping_scales_whole_vector(self):
        # norm of [3.0, 4.0] is 5.0, bound 2.5 -> scale 0.5 -> [1.5, 2.0]
        payload = body(
            [upd("a", [0.0, 0.0], 1), upd("b", [3.0, 4.0], 1)], max_l2_norm=2.5
        )
        response = run(payload)
        self.assertEqual(response["aggregate"], [0.75, 1.0])
        self.assertEqual(response["clipped_participants"], ["b"])

    def test_vector_exactly_at_bound_is_not_clipped(self):
        payload = body([upd("a", [3.0, 4.0], 1), upd("b", [0.0, 0.0], 1)], max_l2_norm=5.0)
        response = run(payload)
        self.assertEqual(response["aggregate"], [1.5, 2.0])
        self.assertEqual(response["clipped_participants"], [])

    def test_zero_vector_never_clipped(self):
        payload = body(
            [upd("a", [0.0, 0.0], 5), upd("b", [0.0, 0.0], 5)], max_l2_norm=0.0001
        )
        response = run(payload)
        self.assertEqual(response["aggregate"], [0.0, 0.0])
        self.assertEqual(response["clipped_participants"], [])

    def test_negative_zero_is_canonicalised(self):
        # (-0.25 + 0.25) / 2 rounds near zero; the result must not be -0.0.
        payload = body(
            [upd("a", [-1.0, 0.0], 1), upd("b", [1.0, 0.0], 1)], max_l2_norm=10.0
        )
        response = run(payload)
        self.assertEqual(response["aggregate"], [0.0, 0.0])
        self.assertNotIn("-", json.dumps(response["aggregate"]))

    def test_clipped_list_sorted_regardless_of_input_order(self):
        payload = body(
            [
                upd("z", [100.0], 1),
                upd("a", [100.0], 1),
                upd("m", [0.0], 1),
            ],
            minimum_participants=3,
            max_l2_norm=1.0,
        )
        response = run(payload)
        self.assertEqual(response["clipped_participants"], ["a", "z"])

    def test_order_does_not_change_aggregate(self):
        updates = [
            upd("a", [1.0, -2.0], 7),
            upd("b", [4.0, 8.0], 3),
            upd("c", [-2.0, 5.0], 11),
        ]
        first = run(body(copy.deepcopy(updates), minimum_participants=3))
        reversed_updates = list(reversed(copy.deepcopy(updates)))
        second = run(body(reversed_updates, minimum_participants=3))
        self.assertEqual(first["aggregate"], second["aggregate"])
        self.assertEqual(first["clipped_participants"], second["clipped_participants"])

    def test_input_is_not_mutated(self):
        updates = [upd("a", [3.0, 4.0], 2), upd("b", [0.0, 0.0], 3)]
        snapshot = copy.deepcopy(updates)
        run(body(updates, max_l2_norm=2.5))
        self.assertEqual(updates, snapshot)

    def test_rounding_is_half_up_to_six_places(self):
        # weighted average 0.1234565 (Decimal exact) -> 0.123457
        payload = body(
            [upd("a", [0.0], 1), upd("b", [0.246913], 1)]
        )
        response = run(payload)
        self.assertEqual(response["aggregate"], [0.123457])

    def test_dimension_reflects_vector_width(self):
        payload = body(
            [upd("a", [1.0] * 4096), upd("b", [2.0] * 4096)], max_l2_norm=10000.0
        )
        response = run(payload)
        self.assertEqual(response["dimension"], 4096)
        self.assertEqual(response["aggregate"], [1.5] * 4096)


class FederatedErrorTest(unittest.TestCase):
    def assert_error(self, payload, error):
        with self.assertRaises(error):
            run(payload)

    def test_root_must_be_object(self):
        for raw in ([], "x", 1, None):
            with self.subTest(raw=raw):
                self.assert_error(raw, InvalidRequest)

    def test_updates_structure(self):
        for bad in (None, [], "x", 1, {}):
            with self.subTest(bad=bad):
                self.assert_error(body(bad), InvalidRequest)

    def test_empty_body_is_invalid_request(self):
        self.assert_error({}, InvalidRequest)

    def test_round_id_invalid(self):
        for value in (None, "", 1, ["x"], True):
            with self.subTest(value=value):
                self.assert_error(body([upd("a", [1.0])], round_id=value), InvalidFederatedConfig)

    def test_minimum_participants_invalid(self):
        for value in (None, 1, 0, 101, 2.0, "2", True, False):
            with self.subTest(value=value):
                self.assert_error(
                    body([upd("a", [1.0])], minimum_participants=value),
                    InvalidFederatedConfig,
                )

    def test_max_l2_norm_invalid(self):
        for value in (None, 0, -1.0, "1", float("inf"), float("-inf"), float("nan"), True):
            with self.subTest(value=value):
                self.assert_error(
                    body([upd("a", [1.0])], max_l2_norm=value),
                    InvalidFederatedConfig,
                )

    def test_update_missing_fields(self):
        base = {"participant_id": "a", "sample_count": 1, "values": [1.0]}
        for field in ("participant_id", "sample_count", "values"):
            item = dict(base)
            del item[field]
            with self.subTest(field=field):
                self.assert_error(body([item]), InvalidUpdate)

    def test_update_entry_not_object(self):
        self.assert_error(body([1, upd("b", [1.0])]), InvalidUpdate)

    def test_participant_id_invalid_or_duplicate(self):
        for bad in (None, "", 1, ["x"]):
            with self.subTest(bad=bad):
                self.assert_error(body([upd(bad, [1.0]), upd("b", [1.0])]), InvalidUpdate)
        self.assert_error(
            body([upd("a", [1.0]), upd("a", [2.0])]), InvalidUpdate
        )

    def test_sample_count_invalid(self):
        for value in (0, -1, 1_000_001, 1.5, "10", True, None):
            with self.subTest(value=value):
                self.assert_error(
                    body([upd("a", [1.0], value), upd("b", [1.0])]), InvalidUpdate
                )

    def test_values_invalid(self):
        for bad in (None, [], "x", [True], [False], [None], ["1"], [{}]):
            with self.subTest(bad=bad):
                self.assert_error(body([upd("a", bad), upd("b", [1.0])]), InvalidUpdate)

    def test_too_many_dimensions(self):
        self.assert_error(
            body([upd("a", [1.0] * 4097), upd("b", [1.0] * 4097)]), InvalidUpdate
        )

    def test_dimension_mismatch(self):
        self.assert_error(
            body([upd("a", [1.0, 2.0]), upd("b", [1.0, 2.0, 3.0])]), InvalidUpdate
        )

    def test_non_finite_numbers_rejected(self):
        self.assert_error(
            body([upd("a", [float("nan")]), upd("b", [1.0])]), InvalidUpdate
        )
        self.assert_error(
            body([upd("a", [float("inf")]), upd("b", [1.0])]), InvalidUpdate
        )

    def test_insufficient_participants(self):
        with self.assertRaises(InsufficientParticipants):
            run(body([upd("a", [1.0])], minimum_participants=2))
        with self.assertRaises(InsufficientParticipants):
            run(
                body(
                    [upd("a", [1.0]), upd("b", [2.0])],
                    minimum_participants=3,
                )
            )

    def test_failure_returns_no_partial_results(self):
        # Updates validated (and the threshold checked) before any release;
        # a malformed later update must never surface earlier vectors.
        with self.assertRaises(InvalidUpdate):
            run(body([upd("a", [100.0]), {"participant_id": "b"}]))


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

    def post(self, payload, content_type="application/json"):
        body_text = payload if isinstance(payload, (str, bytes)) else json.dumps(payload)
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        headers = {"Content-Type": content_type} if content_type is not None else {}
        conn.request("POST", "/v1/federated/aggregate", body=body_text, headers=headers)
        resp = conn.getresponse()
        raw = resp.read()
        conn.close()
        return resp.status, json.loads(raw)

    def test_happy_path_http(self):
        status, payload = self.post(body([upd("a", [1.0], 2), upd("b", [3.0], 2)]))
        self.assertEqual(status, 200)
        self.assertEqual(payload["aggregate"], [2.0])
        self.assertEqual(payload["participant_count"], 2)
        self.assertEqual(payload["total_sample_count"], 4)

    def test_invalid_json(self):
        status, payload = self.post("{not json")
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"]["code"], "invalid_json")

    def test_unsupported_media_type(self):
        status, payload = self.post({}, content_type="text/plain")
        self.assertEqual(status, 415)
        self.assertEqual(payload["error"]["code"], "unsupported_media_type")

    def test_error_codes(self):
        cases = [
            ({}, "invalid_request"),
            (body([], round_id="r"), "invalid_request"),
            (body([upd("a", [1.0])], round_id=""), "invalid_federated_config"),
            (
                body([upd("a", [1.0])], minimum_participants=1),
                "invalid_federated_config",
            ),
            (
                body([upd("a", [1.0])], max_l2_norm=0),
                "invalid_federated_config",
            ),
            (body([{"participant_id": "a"}]), "invalid_update"),
            (body([upd("a", [1.0])]), "insufficient_participants"),
        ]
        for payload, code in cases:
            with self.subTest(code=code):
                status, response = self.post(payload)
                self.assertEqual(status, 422)
                self.assertEqual(response["error"]["code"], code)

    def test_errors_do_not_echo_updates(self):
        secret_vector = [987654.321]
        status, payload = self.post(
            body([upd("secret-participant", secret_vector)], minimum_participants=2)
        )
        self.assertEqual(status, 422)
        encoded = json.dumps(payload)
        self.assertNotIn("secret-participant", encoded)
        self.assertNotIn("987654", encoded)

    def test_method_not_allowed(self):
        for method in ("GET", "PUT", "DELETE", "PATCH"):
            with self.subTest(method=method):
                conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
                conn.request(method, "/v1/federated/aggregate")
                resp = conn.getresponse()
                resp.read()
                conn.close()
                self.assertEqual(resp.status, 405)

    def test_healthz_unchanged(self):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        conn.request("GET", "/healthz")
        resp = conn.getresponse()
        payload = json.loads(resp.read())
        conn.close()
        self.assertEqual(resp.status, 200)
        self.assertEqual(payload["status"], "ok")


if __name__ == "__main__":
    unittest.main()
