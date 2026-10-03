import copy
import http.client
import json
import threading
import unittest
from http.server import ThreadingHTTPServer

from privacare.server import Handler
from privacare.service import Service


class HttpTestBase(unittest.TestCase):
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


def dataset(dataset_id, categories):
    return {"dataset_id": dataset_id, "data_categories": categories}


def transfer(transfer_id, src, dst, categories, at):
    return {
        "transfer_id": transfer_id,
        "from_dataset": src,
        "to_dataset": dst,
        "data_categories": categories,
        "occurred_at": at,
    }


def query(dataset_id, direction, categories, max_depth, as_of=None):
    q = {
        "dataset_id": dataset_id,
        "direction": direction,
        "data_categories": categories,
        "max_depth": max_depth,
    }
    if as_of is not None:
        q["as_of"] = as_of
    return q


def diamond_payload():
    # a -> b -> d ; a -> c -> d ; a -> e (different category only)
    datasets = [
        dataset("a", ["clinical", "contact"]),
        dataset("b", ["clinical"]),
        dataset("c", ["clinical"]),
        dataset("d", ["clinical"]),
        dataset("e", ["contact"]),
    ]
    transfers = [
        transfer("t-ab", "a", "b", ["clinical"], "2026-01-01T00:00:00Z"),
        transfer("t-ac", "a", "c", ["clinical"], "2026-01-02T00:00:00Z"),
        transfer("t-bd", "b", "d", ["clinical"], "2026-02-01T00:00:00Z"),
        transfer("t-cd", "c", "d", ["clinical"], "2026-02-02T00:00:00Z"),
        transfer("t-ae", "a", "e", ["contact"], "2026-03-01T00:00:00Z"),
    ]
    return {"datasets": datasets, "transfers": transfers}


class LineageTraceHttpTest(HttpTestBase):
    def post(self, payload, content_type="application/json"):
        body = payload if isinstance(payload, (str, bytes)) else json.dumps(payload)
        return self.request("POST", "/v1/lineage/trace", body=body, content_type=content_type)

    # --- happy paths -------------------------------------------------------

    def test_downstream_basic(self):
        payload = diamond_payload()
        payload["queries"] = [query("a", "downstream", ["clinical"], 5)]
        status, resp = self.post(payload)
        self.assertEqual(status, 200)
        self.assertEqual(len(resp["results"]), 1)
        result = resp["results"][0]
        self.assertEqual(result["index"], 0)
        self.assertEqual(result["dataset_id"], "a")
        self.assertEqual(result["direction"], "downstream")
        entries = {d["dataset_id"]: d for d in result["datasets"]}
        # e carries no clinical category and must be unreachable
        self.assertEqual(set(entries), {"a", "b", "c", "d"})
        self.assertEqual(entries["a"], {"dataset_id": "a", "distance": 0, "transfer_path": []})
        self.assertEqual(entries["b"]["distance"], 1)
        self.assertEqual(entries["b"]["transfer_path"], ["t-ab"])
        self.assertEqual(entries["c"]["distance"], 1)
        self.assertEqual(entries["c"]["transfer_path"], ["t-ac"])
        self.assertEqual(entries["d"]["distance"], 2)
        # ordered by distance, then dataset_id
        self.assertEqual(
            [(d["dataset_id"], d["distance"]) for d in result["datasets"]],
            [("a", 0), ("b", 1), ("c", 1), ("d", 2)],
        )

    def test_upstream_basic(self):
        payload = diamond_payload()
        payload["queries"] = [query("d", "upstream", ["clinical"], 5)]
        status, resp = self.post(payload)
        self.assertEqual(status, 200)
        entries = {d["dataset_id"]: d for d in resp["results"][0]["datasets"]}
        self.assertEqual(set(entries), {"a", "b", "c", "d"})
        self.assertEqual(entries["d"]["distance"], 0)
        self.assertEqual(entries["b"]["transfer_path"], ["t-bd"])
        self.assertEqual(entries["c"]["transfer_path"], ["t-cd"])
        self.assertEqual(entries["a"]["distance"], 2)

    def test_start_alone_when_nothing_matches(self):
        payload = diamond_payload()
        payload["queries"] = [query("e", "downstream", ["contact"], 5)]
        status, resp = self.post(payload)
        self.assertEqual(status, 200)
        self.assertEqual(
            resp["results"][0]["datasets"],
            [{"dataset_id": "e", "distance": 0, "transfer_path": []}],
        )

    def test_max_depth_limits_reach(self):
        payload = diamond_payload()
        payload["queries"] = [query("a", "downstream", ["clinical"], 1)]
        status, resp = self.post(payload)
        self.assertEqual(status, 200)
        entries = {d["dataset_id"] for d in resp["results"][0]["datasets"]}
        self.assertEqual(entries, {"a", "b", "c"})

    def test_edge_must_carry_all_query_categories(self):
        payload = diamond_payload()
        # a has both clinical+contact, but no single transfer carries both
        payload["queries"] = [query("a", "downstream", ["clinical", "contact"], 5)]
        status, resp = self.post(payload)
        self.assertEqual(status, 200)
        self.assertEqual(
            [d["dataset_id"] for d in resp["results"][0]["datasets"]], ["a"]
        )

    def test_as_of_excludes_later_transfers(self):
        payload = diamond_payload()
        payload["queries"] = [
            query("a", "downstream", ["clinical"], 5, as_of="2026-01-15T00:00:00Z")
        ]
        status, resp = self.post(payload)
        self.assertEqual(status, 200)
        entries = {d["dataset_id"] for d in resp["results"][0]["datasets"]}
        # t-ab (Jan 1) and t-ac (Jan 2) qualify; both edges into d are in February
        self.assertEqual(entries, {"a", "b", "c"})

    def test_as_of_is_inclusive(self):
        payload = diamond_payload()
        payload["queries"] = [
            query("a", "downstream", ["clinical"], 5, as_of="2026-01-01T00:00:00Z")
        ]
        status, resp = self.post(payload)
        self.assertEqual(status, 200)
        entries = {d["dataset_id"] for d in resp["results"][0]["datasets"]}
        self.assertEqual(entries, {"a", "b"})

    def test_tie_break_lexicographic_transfer_sequence(self):
        # Two equal-length paths a->d: via b with ids ["t2"...], via c ["t1"...]
        datasets = [dataset(x, ["clinical"]) for x in ("a", "b", "c", "d")]
        transfers = [
            transfer("t2", "a", "b", ["clinical"], "2026-01-01T00:00:00Z"),
            transfer("t1", "a", "c", ["clinical"], "2026-01-01T00:00:00Z"),
            transfer("t4", "b", "d", ["clinical"], "2026-01-01T00:00:00Z"),
            transfer("t3", "c", "d", ["clinical"], "2026-01-01T00:00:00Z"),
        ]
        payload = {"datasets": datasets, "transfers": transfers,
                   "queries": [query("a", "downstream", ["clinical"], 5)]}
        status, resp = self.post(payload)
        self.assertEqual(status, 200)
        entries = {d["dataset_id"]: d for d in resp["results"][0]["datasets"]}
        # shortest sequences: t1,t3 vs t2,t4 -> lexicographically smallest t1,t3
        self.assertEqual(entries["d"]["transfer_path"], ["t1", "t3"])

    def test_tie_break_propagates_to_descendants(self):
        # d has two length-2 paths; the lexicographically larger first edge is
        # listed first, and d itself has a depth-3 descendant that must inherit
        # the smallest path chosen for d.
        datasets = [dataset(x, ["clinical"]) for x in ("a", "b", "c", "d", "m")]
        transfers = [
            transfer("t9", "a", "b", ["clinical"], "2026-01-01T00:00:00Z"),
            transfer("t0", "b", "d", ["clinical"], "2026-01-01T00:00:00Z"),
            transfer("t1", "a", "c", ["clinical"], "2026-01-01T00:00:00Z"),
            transfer("t2", "c", "d", ["clinical"], "2026-01-01T00:00:00Z"),
            transfer("t3", "d", "m", ["clinical"], "2026-01-01T00:00:00Z"),
        ]
        payload = {"datasets": datasets, "transfers": transfers,
                   "queries": [query("a", "downstream", ["clinical"], 5)]}
        status, resp = self.post(payload)
        self.assertEqual(status, 200)
        entries = {d["dataset_id"]: d for d in resp["results"][0]["datasets"]}
        self.assertEqual(entries["d"]["transfer_path"], ["t1", "t2"])
        self.assertEqual(entries["m"]["transfer_path"], ["t1", "t2", "t3"])

    def test_cycle_has_no_duplicates_or_loop(self):
        datasets = [dataset(x, ["clinical"]) for x in ("a", "b", "c")]
        transfers = [
            transfer("t1", "a", "b", ["clinical"], "2026-01-01T00:00:00Z"),
            transfer("t2", "b", "c", ["clinical"], "2026-01-01T00:00:00Z"),
            transfer("t3", "c", "a", ["clinical"], "2026-01-01T00:00:00Z"),
        ]
        payload = {"datasets": datasets, "transfers": transfers,
                   "queries": [query("a", "downstream", ["clinical"], 20)]}
        status, resp = self.post(payload)
        self.assertEqual(status, 200)
        ids = [d["dataset_id"] for d in resp["results"][0]["datasets"]]
        self.assertEqual(sorted(ids), ["a", "b", "c"])
        self.assertEqual(len(ids), len(set(ids)))

    def test_multiple_queries_in_order(self):
        payload = diamond_payload()
        payload["queries"] = [
            query("d", "upstream", ["clinical"], 1),
            query("a", "downstream", ["clinical"], 1),
        ]
        status, resp = self.post(payload)
        self.assertEqual(status, 200)
        results = resp["results"]
        self.assertEqual([r["index"] for r in results], [0, 1])
        self.assertEqual(results[0]["direction"], "upstream")
        self.assertEqual(results[1]["direction"], "downstream")
        self.assertEqual(
            {d["dataset_id"] for d in results[0]["datasets"]}, {"b", "c", "d"}
        )

    def test_empty_transfers_allowed(self):
        payload = {
            "datasets": [dataset("a", ["clinical"])],
            "transfers": [],
            "queries": [query("a", "downstream", ["clinical"], 3)],
        }
        status, resp = self.post(payload)
        self.assertEqual(status, 200)
        self.assertEqual(len(resp["results"][0]["datasets"]), 1)

    def test_timezone_offsets_compare_as_instants(self):
        datasets = [dataset("a", ["clinical"]), dataset("b", ["clinical"])]
        transfers = [transfer("t1", "a", "b", ["clinical"], "2026-01-01T01:00:00+01:00")]
        payload = {"datasets": datasets, "transfers": transfers,
                   "queries": [query("a", "downstream", ["clinical"], 5,
                                     as_of="2026-01-01T00:30:00+00:00")]}
        status, resp = self.post(payload)
        self.assertEqual(status, 200)
        # transfer at 00:00Z is earlier than 00:30Z
        self.assertEqual(
            [d["dataset_id"] for d in resp["results"][0]["datasets"]], ["a", "b"]
        )

    def test_input_is_not_mutated(self):
        payload = diamond_payload()
        payload["queries"] = [query("a", "downstream", ["clinical"], 5)]
        snapshot = copy.deepcopy(payload)
        self.post(payload)
        self.assertEqual(payload, snapshot)

    # --- HTTP semantics ----------------------------------------------------

    def test_method_not_allowed(self):
        for method in ("GET", "PUT", "DELETE", "PATCH"):
            with self.subTest(method=method):
                status, resp = self.request(method, "/v1/lineage/trace")
                self.assertEqual(status, 405)
                self.assertEqual(resp["error"]["code"], "method_not_allowed")

    def test_unknown_path_404(self):
        status, resp = self.request("POST", "/v1/lineage/nope", body="{}",
                                    content_type="application/json")
        self.assertEqual(status, 404)
        self.assertEqual(resp["error"]["code"], "not_found")

    def test_unsupported_media_type(self):
        status, resp = self.post({}, content_type="text/plain")
        self.assertEqual(status, 415)
        self.assertEqual(resp["error"]["code"], "unsupported_media_type")

    def test_invalid_json(self):
        status, resp = self.post("{not json")
        self.assertEqual(status, 400)
        self.assertEqual(resp["error"]["code"], "invalid_json")

    # --- invalid_request ---------------------------------------------------

    def test_invalid_request(self):
        valid = diamond_payload()
        valid["queries"] = [query("a", "downstream", ["clinical"], 5)]
        cases = [
            "[]",
            "{}",
            json.dumps({k: v for k, v in valid.items() if k != "datasets"}),
            json.dumps({**valid, "datasets": []}),
            json.dumps({**valid, "datasets": "nope"}),
            json.dumps({k: v for k, v in valid.items() if k != "transfers"}),
            json.dumps({**valid, "transfers": "nope"}),
            json.dumps({k: v for k, v in valid.items() if k != "queries"}),
            json.dumps({**valid, "queries": []}),
        ]
        for body in cases:
            with self.subTest(body=body):
                status, resp = self.post(body)
                self.assertEqual(status, 422)
                self.assertEqual(resp["error"]["code"], "invalid_request")

    # --- invalid_dataset ---------------------------------------------------

    def test_invalid_dataset(self):
        valid = diamond_payload()
        valid["queries"] = [query("a", "downstream", ["clinical"], 5)]
        cases = [
            {**valid, "datasets": ["nope"]},
            {**valid, "datasets": [{"data_categories": ["clinical"]}]},
            {**valid, "datasets": [{"dataset_id": "", "data_categories": ["clinical"]}]},
            {**valid, "datasets": [{"dataset_id": "a", "data_categories": []}]},
            {**valid, "datasets": [{"dataset_id": "a", "data_categories": ["nope"]}]},
            {**valid, "datasets": [{"dataset_id": "a", "data_categories": ["clinical", "clinical"]}]},
            {**valid, "datasets": [dataset("a", ["clinical"]), dataset("a", ["clinical"])]},
        ]
        for payload in cases:
            with self.subTest(payload=payload):
                status, resp = self.post(payload)
                self.assertEqual(status, 422)
                self.assertEqual(resp["error"]["code"], "invalid_dataset")

    # --- invalid_transfer --------------------------------------------------

    def test_invalid_transfer(self):
        valid = diamond_payload()
        valid["queries"] = [query("a", "downstream", ["clinical"], 5)]
        dup = transfer("t-ab", "a", "b", ["clinical"], "2026-01-01T00:00:00Z")
        cases = [
            {**valid, "transfers": ["nope"]},
            {**valid, "transfers": [{**valid["transfers"][0], "transfer_id": ""}]},
            {**valid, "transfers": [{**valid["transfers"][0], "from_dataset": ""}]},
            {**valid, "transfers": [
                {**valid["transfers"][0], "from_dataset": "a", "to_dataset": "a"}]},
            {**valid, "transfers": [
                {**valid["transfers"][0], "from_dataset": "ghost", "to_dataset": "b"}]},
            {**valid, "transfers": [
                {**valid["transfers"][0], "from_dataset": "a", "to_dataset": "ghost"}]},
            {**valid, "transfers": [
                {**valid["transfers"][0], "occurred_at": "2026-01-01T00:00:00"}]},
            {**valid, "transfers": [
                {**valid["transfers"][0], "occurred_at": "not-a-time"}]},
            {**valid, "transfers": [
                {**valid["transfers"][0], "data_categories": ["clinical", "clinical"]}]},
            {**valid, "transfers": [
                {**valid["transfers"][0], "data_categories": ["nope"]}]},
            {**valid, "transfers": [valid["transfers"][0], dup]},
        ]
        # category not a subset of the source/target dataset categories
        case_source = copy.deepcopy(valid)
        case_source["transfers"][0]["data_categories"] = ["contact"]  # b lacks contact
        cases.append(case_source)
        for payload in cases:
            with self.subTest(payload=json.dumps(payload)[:80]):
                status, resp = self.post(payload)
                self.assertEqual(status, 422)
                self.assertEqual(resp["error"]["code"], "invalid_transfer")

    # --- invalid_query -----------------------------------------------------

    def test_invalid_query(self):
        valid = diamond_payload()
        valid["queries"] = [query("a", "downstream", ["clinical"], 5)]
        cases = [
            {**valid, "queries": ["nope"]},
            {**valid, "queries": [{**valid["queries"][0], "dataset_id": "ghost"}]},
            {**valid, "queries": [{**valid["queries"][0], "dataset_id": ""}]},
            {**valid, "queries": [{**valid["queries"][0], "direction": "sideways"}]},
            {**valid, "queries": [{k: v for k, v in valid["queries"][0].items()
                                   if k != "direction"}]},
            {**valid, "queries": [{**valid["queries"][0], "data_categories": []}]},
            {**valid, "queries": [{**valid["queries"][0], "data_categories": ["clinical", "clinical"]}]},
        ]
        # Query categories must be a subset of the START dataset's categories.
        subset_case = {**valid, "queries": [query("b", "downstream", ["contact"], 5)]}
        cases.append(subset_case)
        cases += [
            {**valid, "queries": [{**valid["queries"][0], "data_categories": ["nope"]}]},
            {**valid, "queries": [{**valid["queries"][0], "max_depth": 0}]},
            {**valid, "queries": [{**valid["queries"][0], "max_depth": 21}]},
            {**valid, "queries": [{**valid["queries"][0], "max_depth": True}]},
            {**valid, "queries": [{**valid["queries"][0], "max_depth": 1.0}]},
            {**valid, "queries": [{**valid["queries"][0], "max_depth": "5"}]},
            {**valid, "queries": [{**valid["queries"][0], "as_of": "2026-01-01"}]},
            {**valid, "queries": [{**valid["queries"][0], "as_of": "nope"}]},
            {**valid, "queries": [{k: v for k, v in valid["queries"][0].items()
                                   if k != "max_depth"}]},
        ]
        for payload in cases:
            with self.subTest(payload=json.dumps(payload)[:100]):
                status, resp = self.post(payload)
                self.assertEqual(status, 422)
                self.assertEqual(resp["error"]["code"], "invalid_query")

    def test_no_partial_results_on_failure(self):
        payload = diamond_payload()
        payload["queries"] = [
            query("a", "downstream", ["clinical"], 5),
            query("a", "downstream", ["clinical"], 0),  # invalid second query
        ]
        status, resp = self.post(payload)
        self.assertEqual(status, 422)
        self.assertEqual(resp["error"]["code"], "invalid_query")
        self.assertNotIn("results", resp)


class LineageServiceTest(unittest.TestCase):
    def test_service_method(self):
        payload = diamond_payload()
        payload["queries"] = [query("a", "downstream", ["clinical"], 5)]
        result = Service().trace_lineage(copy.deepcopy(payload))
        self.assertIn("results", result)
        self.assertEqual(result["results"][0]["dataset_id"], "a")


if __name__ == "__main__":
    unittest.main()
