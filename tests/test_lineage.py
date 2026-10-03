import copy
import http.client
import json
import threading
import unittest
from http.server import ThreadingHTTPServer

from privacare.classifier import InvalidRequest
from privacare.lineage import (
    InvalidDataset,
    InvalidQuery,
    InvalidTransfer,
    trace_lineage,
)
from privacare.server import Handler
from privacare.service import Service

CLINICAL = "clinical"
CONTACT = "contact"
FINANCIAL = "financial"


def ds(dataset_id, cats):
    return {"dataset_id": dataset_id, "data_categories": cats}


def tr(transfer_id, src, dst, cats, at="2026-03-01T00:00:00Z"):
    return {
        "transfer_id": transfer_id,
        "from_dataset": src,
        "to_dataset": dst,
        "occurred_at": at,
        "data_categories": cats,
    }


def q(dataset_id, direction, cats, max_depth=5, as_of=None):
    query = {
        "dataset_id": dataset_id,
        "direction": direction,
        "data_categories": cats,
        "max_depth": max_depth,
    }
    if as_of is not None:
        query["as_of"] = as_of
    return query


# Diamond: a -> b (ta), a -> c (tb), b -> d (tc), c -> d (td)
DIAMOND = {
    "datasets": [
        ds("a", [CLINICAL, CONTACT]),
        ds("b", [CLINICAL]),
        ds("c", [CLINICAL, FINANCIAL]),
        ds("d", [CLINICAL]),
    ],
    "transfers": [
        tr("ta", "a", "b", [CLINICAL]),
        tr("tb", "a", "c", [CLINICAL]),
        tr("tc", "b", "d", [CLINICAL]),
        tr("td", "c", "d", [CLINICAL]),
    ],
    "queries": [q("a", "downstream", [CLINICAL])],
}


class TraceLineageUnitTest(unittest.TestCase):
    def result_for(self, payload, index=0):
        return trace_lineage(payload)["results"][index]

    def test_start_alone_when_no_edges(self):
        payload = {
            "datasets": [ds("a", [CLINICAL])],
            "transfers": [],
            "queries": [q("a", "downstream", [CLINICAL])],
        }
        result = self.result_for(payload)
        self.assertEqual(
            result["datasets"],
            [{"dataset_id": "a", "distance": 0, "transfer_path": []}],
        )

    def test_downstream_distances_and_ordering(self):
        result = self.result_for(DIAMOND)
        self.assertEqual(result["index"], 0)
        self.assertEqual(result["dataset_id"], "a")
        self.assertEqual(result["direction"], "downstream")
        entries = result["datasets"]
        self.assertEqual(
            [(e["dataset_id"], e["distance"]) for e in entries],
            [("a", 0), ("b", 1), ("c", 1), ("d", 2)],
        )
        self.assertEqual(entries[0]["transfer_path"], [])

    def test_upstream_mirrors_direction(self):
        payload = copy.deepcopy(DIAMOND)
        payload["queries"] = [q("d", "upstream", [CLINICAL])]
        entries = self.result_for(payload)["datasets"]
        self.assertEqual(
            [(e["dataset_id"], e["distance"]) for e in entries],
            [("d", 0), ("b", 1), ("c", 1), ("a", 2)],
        )

    def test_lexicographically_smallest_shortest_path_wins(self):
        entries = {e["dataset_id"]: e for e in self.result_for(DIAMOND)["datasets"]}
        # [ta, tc] < [tb, td] because ta < tb.
        self.assertEqual(entries["d"]["transfer_path"], ["ta", "tc"])
        self.assertEqual(entries["d"]["distance"], 2)

    def test_upstream_lexicographic_tie(self):
        payload = copy.deepcopy(DIAMOND)
        payload["queries"] = [q("d", "upstream", [CLINICAL])]
        entries = {e["dataset_id"]: e for e in self.result_for(payload)["datasets"]}
        self.assertEqual(entries["a"]["transfer_path"], ["tc", "ta"])

    def test_other_shortest_path_chosen_when_ids_reversed(self):
        payload = copy.deepcopy(DIAMOND)
        payload["transfers"] = [
            tr("t1", "a", "b", [CLINICAL]),
            tr("t0", "a", "c", [CLINICAL]),
            tr("t3", "b", "d", [CLINICAL]),
            tr("t2", "c", "d", [CLINICAL]),
        ]
        entries = {e["dataset_id"]: e for e in self.result_for(payload)["datasets"]}
        self.assertEqual(entries["d"]["transfer_path"], ["t0", "t2"])

    def test_cycles_do_not_duplicate_or_loop(self):
        payload = copy.deepcopy(DIAMOND)
        # d -> a closes a cycle a-b-d-a.
        payload["transfers"].append(tr("te", "d", "a", [CLINICAL]))
        entries = self.result_for(payload)["datasets"]
        ids = [e["dataset_id"] for e in entries]
        self.assertEqual(ids, ["a", "b", "c", "d"])
        self.assertEqual(ids.count("a"), 1)

    def test_self_reach_via_cycle_keeps_zero_path(self):
        payload = copy.deepcopy(DIAMOND)
        payload["transfers"].append(tr("te", "d", "a", [CLINICAL]))
        start = self.result_for(payload)["datasets"][0]
        self.assertEqual(start, {"dataset_id": "a", "distance": 0, "transfer_path": []})

    def test_as_of_filters_edges_not_later_than_it(self):
        payload = {
            "datasets": [ds("a", [CLINICAL]), ds("x", [CLINICAL]), ds("y", [CLINICAL])],
            "transfers": [
                tr("t1", "a", "x", [CLINICAL], "2026-01-01T00:00:00Z"),
                tr("t2", "x", "y", [CLINICAL], "2026-03-01T00:00:00Z"),
            ],
            "queries": [q("a", "downstream", [CLINICAL], as_of="2026-02-01T00:00:00Z")],
        }
        entries = self.result_for(payload)["datasets"]
        self.assertEqual([e["dataset_id"] for e in entries], ["a", "x"])

    def test_as_of_boundary_is_inclusive(self):
        payload = {
            "datasets": [ds("a", [CLINICAL]), ds("x", [CLINICAL])],
            "transfers": [tr("t1", "a", "x", [CLINICAL], "2026-01-01T08:00:00+08:00")],
            "queries": [q("a", "downstream", [CLINICAL], as_of="2026-01-01T00:00:00Z")],
        }
        entries = self.result_for(payload)["datasets"]
        self.assertEqual([e["dataset_id"] for e in entries], ["a", "x"])

    def test_without_as_of_all_transfers_used(self):
        payload = {
            "datasets": [ds("a", [CLINICAL]), ds("x", [CLINICAL]), ds("y", [CLINICAL])],
            "transfers": [
                tr("t1", "a", "x", [CLINICAL], "2026-01-01T00:00:00Z"),
                tr("t2", "x", "y", [CLINICAL], "2099-03-01T00:00:00Z"),
            ],
            "queries": [q("a", "downstream", [CLINICAL])],
        }
        entries = self.result_for(payload)["datasets"]
        self.assertEqual([e["dataset_id"] for e in entries], ["a", "x", "y"])

    def test_transfer_must_carry_all_query_categories(self):
        payload = {
            "datasets": [
                ds("a", [CLINICAL, CONTACT]),
                ds("x", [CLINICAL, CONTACT]),
            ],
            "transfers": [tr("t1", "a", "x", [CLINICAL])],
            "queries": [q("a", "downstream", [CLINICAL, CONTACT])],
        }
        entries = self.result_for(payload)["datasets"]
        self.assertEqual([e["dataset_id"] for e in entries], ["a"])

    def test_multi_category_traversal_when_covered(self):
        payload = {
            "datasets": [
                ds("a", [CLINICAL, CONTACT]),
                ds("x", [CLINICAL, CONTACT]),
            ],
            "transfers": [tr("t1", "a", "x", [CONTACT, CLINICAL])],
            "queries": [q("a", "downstream", [CLINICAL, CONTACT])],
        }
        entries = self.result_for(payload)["datasets"]
        self.assertEqual(entries[1]["transfer_path"], ["t1"])

    def test_max_depth_bounds_reach(self):
        payload = {
            "datasets": [ds("a", [CLINICAL]), ds("b", [CLINICAL]), ds("c", [CLINICAL]), ds("d", [CLINICAL])],
            "transfers": [
                tr("t1", "a", "b", [CLINICAL]),
                tr("t2", "b", "c", [CLINICAL]),
                tr("t3", "c", "d", [CLINICAL]),
            ],
            "queries": [q("a", "downstream", [CLINICAL], max_depth=2)],
        }
        entries = self.result_for(payload)["datasets"]
        self.assertEqual(
            [(e["dataset_id"], e["distance"]) for e in entries],
            [("a", 0), ("b", 1), ("c", 2)],
        )

    def test_depth_one_only_direct_neighbors(self):
        entries = self.result_for(
            {**DIAMOND, "queries": [q("a", "downstream", [CLINICAL], max_depth=1)]}
        )["datasets"]
        self.assertEqual([e["dataset_id"] for e in entries], ["a", "b", "c"])

    def test_multiple_queries_preserve_order_and_echo(self):
        payload = copy.deepcopy(DIAMOND)
        payload["queries"] = [
            q("a", "downstream", [CLINICAL], max_depth=1),
            q("d", "upstream", [CLINICAL], max_depth=1),
        ]
        results = trace_lineage(payload)["results"]
        self.assertEqual([r["index"] for r in results], [0, 1])
        self.assertEqual(results[0]["dataset_id"], "a")
        self.assertEqual(results[0]["direction"], "downstream")
        self.assertEqual(results[1]["dataset_id"], "d")
        self.assertEqual(results[1]["direction"], "upstream")

    def test_input_is_not_mutated(self):
        payload = copy.deepcopy(DIAMOND)
        snapshot = copy.deepcopy(payload)
        trace_lineage(payload)
        self.assertEqual(payload, snapshot)

    def test_service_method(self):
        output = Service().trace_lineage(
            {
                "datasets": [ds("a", [CLINICAL])],
                "transfers": [],
                "queries": [q("a", "downstream", [CLINICAL])],
            }
        )
        self.assertIn("results", output)
        self.assertEqual(output["results"][0]["datasets"][0]["distance"], 0)


class TraceLineageValidationTest(unittest.TestCase):
    def assert_invalid(self, payload, error):
        with self.assertRaises(error):
            trace_lineage(payload)

    def test_root_and_array_errors_are_invalid_request(self):
        good_ds = [ds("a", [CLINICAL])]
        good_q = [q("a", "downstream", [CLINICAL])]
        for payload in (
            [],
            "nope",
            {"transfers": [], "queries": good_q},
            {"datasets": [], "transfers": [], "queries": good_q},
            {"datasets": good_ds, "queries": good_q},
            {"datasets": good_ds, "transfers": "x", "queries": good_q},
            {"datasets": good_ds, "transfers": []},
            {"datasets": good_ds, "transfers": [], "queries": []},
        ):
            with self.subTest(payload=payload):
                self.assert_invalid(payload, InvalidRequest)

    def test_dataset_errors(self):
        base = {"transfers": [], "queries": [q("a", "downstream", [CLINICAL])]}
        bad_datasets = [
            ["nope"],
            [{"data_categories": [CLINICAL]}],
            [{"dataset_id": "a"}],
            [{"dataset_id": "", "data_categories": [CLINICAL]}],
            [{"dataset_id": 1, "data_categories": [CLINICAL]}],
            [ds("a", [])],
            [ds("a", ["nope"])],
            [ds("a", [CLINICAL, CLINICAL])],
            [ds("a", [1])],
            [ds("a", [CLINICAL]), ds("a", [CONTACT])],
        ]
        for datasets in bad_datasets:
            with self.subTest(datasets=datasets):
                self.assert_invalid({**base, "datasets": datasets}, InvalidDataset)

    def test_transfer_field_errors(self):
        datasets = [ds("a", [CLINICAL]), ds("b", [CLINICAL, CONTACT])]
        base = {"datasets": datasets, "queries": [q("a", "downstream", [CLINICAL])]}
        bad_transfers = [
            ["nope"],
            [{"to_dataset": "b", "occurred_at": "2026-01-01T00:00:00Z", "data_categories": [CLINICAL]}],
            [tr("", "a", "b", [CLINICAL])],
            [tr("t1", "a", "a", [CLINICAL])],
            [tr("t1", "a", "zzz", [CLINICAL])],
            [tr("t1", "zzz", "b", [CLINICAL])],
            [tr("t1", "a", "b", [CLINICAL], "2026-01-01T00:00:00")],
            [tr("t1", "a", "b", [CLINICAL], "not-a-time")],
            [tr("t1", "a", "b", [])],
            [tr("t1", "a", "b", ["nope"])],
            [tr("t1", "a", "b", [CONTACT])],
            [tr("t1", "a", "b", [CLINICAL, CONTACT])],
            [tr("t1", "a", "b", [CLINICAL]), tr("t1", "a", "b", [CLINICAL])],
        ]
        for transfers in bad_transfers:
            with self.subTest(transfers=transfers):
                self.assert_invalid({**base, "transfers": transfers}, InvalidTransfer)

    def test_transfer_category_subset_of_both_endpoints(self):
        # b has no contact: transfer of contact invalid even though a has it.
        payload = {
            "datasets": [ds("a", [CLINICAL, CONTACT]), ds("b", [CLINICAL])],
            "transfers": [tr("t1", "a", "b", [CONTACT])],
            "queries": [q("a", "downstream", [CLINICAL])],
        }
        self.assert_invalid(payload, InvalidTransfer)

    def test_query_errors(self):
        datasets = [ds("a", [CLINICAL])]
        base = {"datasets": datasets, "transfers": []}
        bad_queries = [
            ["nope"],
            [{"direction": "downstream", "data_categories": [CLINICAL], "max_depth": 1}],
            [{"dataset_id": "a", "data_categories": [CLINICAL], "max_depth": 1}],
            [{"dataset_id": "a", "direction": "sideways", "data_categories": [CLINICAL], "max_depth": 1}],
            [q("zzz", "downstream", [CLINICAL])],
            [q("a", "downstream", [])],
            [q("a", "downstream", ["nope"])],
            [q("a", "downstream", [CONTACT])],
            [q("a", "downstream", [CLINICAL, CLINICAL])],
        ]
        for queries in bad_queries:
            with self.subTest(queries=queries):
                self.assert_invalid({**base, "queries": queries}, InvalidQuery)

    def test_max_depth_rejects_bools_floats_and_out_of_range(self):
        base = {
            "datasets": [ds("a", [CLINICAL])],
            "transfers": [],
        }
        for depth in (True, False, 0, 21, 1.0, "1", -1, None):
            with self.subTest(depth=depth):
                self.assert_invalid(
                    {**base, "queries": [q("a", "downstream", [CLINICAL], max_depth=depth)]},
                    InvalidQuery,
                )

    def test_max_depth_accepts_bounds(self):
        payload = {
            "datasets": [ds("a", [CLINICAL]), ds("b", [CLINICAL])],
            "transfers": [tr("t1", "a", "b", [CLINICAL])],
        }
        for depth in (1, 20):
            with self.subTest(depth=depth):
                output = trace_lineage(
                    {**payload, "queries": [q("a", "downstream", [CLINICAL], max_depth=depth)]}
                )
                self.assertEqual(output["results"][0]["datasets"][-1]["dataset_id"], "b")

    def test_as_of_must_be_timezoned_rfc3339(self):
        payload = {
            "datasets": [ds("a", [CLINICAL])],
            "transfers": [],
            "queries": [q("a", "downstream", [CLINICAL], as_of="2026-01-01T00:00:00")],
        }
        self.assert_invalid(payload, InvalidQuery)


class LineageHttpTest(unittest.TestCase):
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
        body = payload if isinstance(payload, (str, bytes)) else json.dumps(payload)
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        headers = {"Content-Type": content_type} if content_type else {}
        conn.request("POST", "/v1/lineage/trace", body=body, headers=headers)
        resp = conn.getresponse()
        raw = resp.read()
        conn.close()
        return resp.status, json.loads(raw)

    def request(self, method, path):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        conn.request(method, path)
        resp = conn.getresponse()
        raw = resp.read()
        conn.close()
        return resp.status, json.loads(raw)

    def test_happy_path_http(self):
        status, payload = self.post(DIAMOND)
        self.assertEqual(status, 200)
        result = payload["results"][0]
        self.assertEqual(
            [(e["dataset_id"], e["distance"]) for e in result["datasets"]],
            [("a", 0), ("b", 1), ("c", 1), ("d", 2)],
        )

    def test_error_codes(self):
        cases = [
            ({}, "invalid_request"),
            (
                {
                    "datasets": [ds("a", [CLINICAL])],
                    "transfers": [],
                    "queries": [q("a", "downstream", [CLINICAL])],
                    "extra": None,
                },
                None,
            ),
            (
                {
                    "datasets": [ds("a", ["bogus"])],
                    "transfers": [],
                    "queries": [q("a", "downstream", [CLINICAL])],
                },
                "invalid_dataset",
            ),
            (
                {
                    "datasets": [ds("a", [CLINICAL]), ds("b", [CLINICAL])],
                    "transfers": [tr("t1", "a", "b", ["bogus"])],
                    "queries": [q("a", "downstream", [CLINICAL])],
                },
                "invalid_transfer",
            ),
            (
                {
                    "datasets": [ds("a", [CLINICAL])],
                    "transfers": [],
                    "queries": [q("a", "sideways", [CLINICAL])],
                },
                "invalid_query",
            ),
        ]
        for payload, code in cases:
            with self.subTest(code=code):
                status, body = self.post(payload)
                if code is None:
                    self.assertEqual(status, 200)
                else:
                    self.assertEqual(status, 422)
                    self.assertEqual(body["error"]["code"], code)

    def test_unsupported_media_type_and_json(self):
        status, payload = self.post({"datasets": []}, content_type="text/plain")
        self.assertEqual(status, 415)
        self.assertEqual(payload["error"]["code"], "unsupported_media_type")
        status, payload = self.post("{not json")
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"]["code"], "invalid_json")

    def test_method_not_allowed_and_unknown_path(self):
        for method in ("GET", "PUT", "DELETE", "PATCH"):
            status, payload = self.request(method, "/v1/lineage/trace")
            self.assertEqual(status, 405)
            self.assertEqual(payload["error"]["code"], "method_not_allowed")
        status, payload = self.request("GET", "/v1/nope")
        self.assertEqual(status, 404)
        self.assertEqual(payload["error"]["code"], "not_found")

    def test_error_returns_no_partial_results(self):
        bad = {
            "datasets": [ds("a", [CLINICAL]), ds("b", [CLINICAL])],
            "transfers": [tr("t1", "a", "b", ["bogus"])],
            "queries": [q("a", "downstream", [CLINICAL])],
        }
        status, payload = self.post(bad)
        self.assertEqual(status, 422)
        self.assertNotIn("results", payload)
        self.assertEqual(set(payload.keys()), {"error"})


if __name__ == "__main__":
    unittest.main()
