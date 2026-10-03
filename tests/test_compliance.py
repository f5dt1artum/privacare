import copy
import http.client
import json
import threading
import unittest
from http.server import ThreadingHTTPServer

from privacare import __version__
from privacare.server import Handler

PATH = "/v1/compliance/transfer/evaluate"


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


def make_rule(**overrides):
    rule = {
        "rule_id": "r-1",
        "priority": 10,
        "effect": "allow",
        "source_jurisdictions": ["CN"],
        "destination_jurisdictions": ["EU"],
        "purposes": ["treatment"],
        "legal_bases": ["consent"],
        "data_categories": ["clinical", "contact"],
        "valid_from": "2026-01-01T00:00:00Z",
        "valid_until": "2026-12-31T23:59:59Z",
    }
    rule.update(overrides)
    return rule


def make_transfer(**overrides):
    transfer = {
        "transfer_id": "t-1",
        "source_jurisdiction": "CN",
        "destination_jurisdiction": "EU",
        "purpose": "treatment",
        "legal_basis": "consent",
        "data_categories": ["clinical"],
        "requested_at": "2026-06-01T12:00:00Z",
    }
    transfer.update(overrides)
    return transfer


class TransferEvaluateHttpTest(HttpTestBase):
    def post(self, payload, content_type="application/json"):
        body = payload if isinstance(payload, (str, bytes)) else json.dumps(payload)
        return self.request("POST", PATH, body=body, content_type=content_type)

    def test_healthz_unchanged(self):
        status, payload = self.request("GET", "/healthz")
        self.assertEqual(status, 200)
        self.assertEqual(
            payload,
            {"status": "ok", "service": "privacare", "version": __version__},
        )

    def test_allow_and_default_deny(self):
        status, payload = self.post(
            {
                "rules": [make_rule()],
                "transfers": [
                    make_transfer(),
                    make_transfer(transfer_id="t-2", purpose="research"),
                    make_transfer(transfer_id="t-3", legal_basis="contract"),
                    make_transfer(transfer_id="t-4", source_jurisdiction="US"),
                    make_transfer(transfer_id="t-5", destination_jurisdiction="US"),
                    make_transfer(transfer_id="t-6", data_categories=["financial"]),
                ],
            }
        )
        self.assertEqual(status, 200)
        results = payload["results"]
        self.assertEqual([r["index"] for r in results], [0, 1, 2, 3, 4, 5])
        self.assertEqual(
            results[0],
            {
                "index": 0,
                "transfer_id": "t-1",
                "allowed": True,
                "reason": "transfer_allowed",
                "rule_id": "r-1",
            },
        )
        for result in results[1:]:
            self.assertEqual(result["allowed"], False)
            self.assertEqual(result["reason"], "no_matching_rule")
            self.assertNotIn("rule_id", result)

    def test_deny_rule_hit(self):
        status, payload = self.post(
            {
                "rules": [make_rule(effect="deny")],
                "transfers": [make_transfer()],
            }
        )
        self.assertEqual(status, 200)
        self.assertEqual(
            payload["results"][0],
            {
                "index": 0,
                "transfer_id": "t-1",
                "allowed": False,
                "reason": "transfer_denied",
                "rule_id": "r-1",
            },
        )

    def test_category_subset_matching(self):
        # 流转类别是规则类别的子集才匹配；超出则不匹配。
        status, payload = self.post(
            {
                "rules": [make_rule()],
                "transfers": [
                    make_transfer(data_categories=["clinical", "contact"]),
                    make_transfer(transfer_id="t-2", data_categories=["clinical", "financial"]),
                ],
            }
        )
        self.assertEqual(status, 200)
        self.assertEqual([r["allowed"] for r in payload["results"]], [True, False])

    def test_time_window_boundaries(self):
        # requested_at == valid_from 匹配；== valid_until 不匹配。
        status, payload = self.post(
            {
                "rules": [make_rule()],
                "transfers": [
                    make_transfer(requested_at="2026-01-01T00:00:00Z"),
                    make_transfer(transfer_id="t-2", requested_at="2025-12-31T23:59:59Z"),
                    make_transfer(transfer_id="t-3", requested_at="2026-12-31T23:59:58Z"),
                    make_transfer(transfer_id="t-4", requested_at="2026-12-31T23:59:59Z"),
                ],
            }
        )
        self.assertEqual(status, 200)
        self.assertEqual(
            [r["allowed"] for r in payload["results"]],
            [True, False, True, False],
        )

    def test_timezone_offsets_compare_by_instant(self):
        status, payload = self.post(
            {
                "rules": [make_rule(valid_from="2026-01-01T08:00:00+08:00")],
                "transfers": [make_transfer(requested_at="2026-01-01T00:00:00Z")],
            }
        )
        self.assertEqual(status, 200)
        self.assertEqual(payload["results"][0]["allowed"], True)

    def test_highest_priority_wins(self):
        status, payload = self.post(
            {
                "rules": [
                    make_rule(rule_id="r-low", priority=1, effect="deny"),
                    make_rule(rule_id="r-high", priority=1000),
                ],
                "transfers": [make_transfer()],
            }
        )
        self.assertEqual(status, 200)
        self.assertEqual(payload["results"][0]["rule_id"], "r-high")
        self.assertEqual(payload["results"][0]["allowed"], True)

    def test_deny_wins_priority_tie(self):
        status, payload = self.post(
            {
                "rules": [
                    make_rule(rule_id="r-allow", priority=5),
                    make_rule(rule_id="r-deny", priority=5, effect="deny"),
                ],
                "transfers": [make_transfer()],
            }
        )
        self.assertEqual(status, 200)
        result = payload["results"][0]
        self.assertEqual(result["allowed"], False)
        self.assertEqual(result["reason"], "transfer_denied")
        self.assertEqual(result["rule_id"], "r-deny")

    def test_smallest_rule_id_breaks_remaining_tie(self):
        status, payload = self.post(
            {
                "rules": [
                    make_rule(rule_id="r-b", priority=5),
                    make_rule(rule_id="r-a", priority=5),
                ],
                "transfers": [make_transfer()],
            }
        )
        self.assertEqual(status, 200)
        self.assertEqual(payload["results"][0]["rule_id"], "r-a")

    def test_rules_never_combined(self):
        # 一条规则覆盖来源/目的，另一条覆盖类别；不得拼接。
        status, payload = self.post(
            {
                "rules": [
                    make_rule(rule_id="r-1", data_categories=["clinical"]),
                    make_rule(rule_id="r-2", purposes=["research"], data_categories=["clinical"]),
                ],
                "transfers": [make_transfer(data_categories=["clinical", "contact"])],
            }
        )
        self.assertEqual(status, 200)
        self.assertEqual(payload["results"][0]["reason"], "no_matching_rule")

    def test_response_does_not_echo_rule_details(self):
        status, payload = self.post(
            {
                "rules": [make_rule()],
                "transfers": [make_transfer()],
            }
        )
        self.assertEqual(status, 200)
        body = json.dumps(payload)
        self.assertNotIn("treatment", body)
        self.assertNotIn("clinical", body)
        self.assertNotIn("CN", body)
        self.assertNotIn("EU", body)

    def test_no_mutation_and_deterministic(self):
        payload = {
            "rules": [make_rule(), make_rule(rule_id="r-2", priority=1, effect="deny")],
            "transfers": [make_transfer(), make_transfer(transfer_id="t-2", purpose="x")],
        }
        snapshot = copy.deepcopy(payload)
        status, first = self.post(payload)
        self.assertEqual(status, 200)
        self.assertEqual(payload, snapshot)
        status, second = self.post(payload)
        self.assertEqual(status, 200)
        self.assertEqual(first, second)

    def test_invalid_request(self):
        for body in (
            "[]",
            "{}",
            '{"rules": []}',
            '{"transfers": []}',
            '{"rules": [], "transfers": [{}]}',
            '{"rules": [{}], "transfers": []}',
            '{"rules": {}, "transfers": [{}]}',
            '{"rules": [{}], "transfers": {}}',
        ):
            with self.subTest(body=body):
                status, payload = self.post(body)
                self.assertEqual(status, 422)
                self.assertEqual(payload["error"]["code"], "invalid_request")

    def test_invalid_rule(self):
        base = make_rule()
        cases = []
        for field in (
            "rule_id",
            "priority",
            "effect",
            "source_jurisdictions",
            "destination_jurisdictions",
            "purposes",
            "legal_bases",
            "data_categories",
            "valid_from",
            "valid_until",
        ):
            broken = {k: v for k, v in base.items() if k != field}
            cases.append(broken)
        cases += [
            "not-an-object",
            make_rule(rule_id=""),
            make_rule(priority=-1),
            make_rule(priority=1001),
            make_rule(priority=1.5),
            make_rule(priority=True),
            make_rule(priority="10"),
            make_rule(effect="permit"),
            make_rule(effect=""),
            make_rule(source_jurisdictions=[]),
            make_rule(source_jurisdictions=["CN", "CN"]),
            make_rule(source_jurisdictions=["CN", 1]),
            make_rule(destination_jurisdictions=[]),
            make_rule(destination_jurisdictions=["EU", "EU"]),
            make_rule(purposes=[]),
            make_rule(purposes=["a", "a"]),
            make_rule(legal_bases=[]),
            make_rule(legal_bases=["consent", "consent"]),
            make_rule(data_categories=[]),
            make_rule(data_categories=["clinical", "clinical"]),
            make_rule(data_categories=["unknown"]),
            make_rule(valid_from="2026-01-01"),
            make_rule(valid_from="2026-01-01T00:00:00"),
            make_rule(valid_until="not-a-time"),
            make_rule(valid_until="2026-01-01T00:00:00Z"),  # equal to valid_from
            make_rule(
                valid_from="2026-06-01T00:00:00Z",
                valid_until="2026-01-01T00:00:00Z",
            ),
        ]
        for rule in cases:
            with self.subTest(rule=rule):
                status, payload = self.post(
                    {"rules": [rule], "transfers": [make_transfer()]}
                )
                self.assertEqual(status, 422)
                self.assertEqual(payload["error"]["code"], "invalid_rule")

    def test_duplicate_rule_id(self):
        status, payload = self.post(
            {
                "rules": [make_rule(), make_rule(priority=20)],
                "transfers": [make_transfer()],
            }
        )
        self.assertEqual(status, 422)
        self.assertEqual(payload["error"]["code"], "invalid_rule")

    def test_invalid_transfer(self):
        base = make_transfer()
        cases = []
        for field in (
            "transfer_id",
            "source_jurisdiction",
            "destination_jurisdiction",
            "purpose",
            "legal_basis",
            "data_categories",
            "requested_at",
        ):
            broken = {k: v for k, v in base.items() if k != field}
            cases.append(broken)
        cases += [
            "not-an-object",
            make_transfer(transfer_id=""),
            make_transfer(source_jurisdiction=""),
            make_transfer(destination_jurisdiction=""),
            make_transfer(source_jurisdiction="EU", destination_jurisdiction="EU"),
            make_transfer(purpose=""),
            make_transfer(legal_basis=""),
            make_transfer(data_categories=[]),
            make_transfer(data_categories=["clinical", "clinical"]),
            make_transfer(data_categories=["unknown"]),
            make_transfer(data_categories=["clinical", 1]),
            make_transfer(requested_at="2026-06-01"),
            make_transfer(requested_at="2026-06-01T12:00:00"),
            make_transfer(requested_at="not-a-time"),
        ]
        for transfer in cases:
            with self.subTest(transfer=transfer):
                status, payload = self.post(
                    {"rules": [make_rule()], "transfers": [transfer]}
                )
                self.assertEqual(status, 422)
                self.assertEqual(payload["error"]["code"], "invalid_transfer")

    def test_duplicate_transfer_id(self):
        status, payload = self.post(
            {
                "rules": [make_rule()],
                "transfers": [make_transfer(), make_transfer()],
            }
        )
        self.assertEqual(status, 422)
        self.assertEqual(payload["error"]["code"], "invalid_transfer")

    def test_no_partial_results_and_error_does_not_echo_input(self):
        payload = {
            "rules": [make_rule()],
            "transfers": [make_transfer(), make_transfer(transfer_id="t-secret", purpose="")],
        }
        status, body = self.post(payload)
        self.assertEqual(status, 422)
        self.assertNotIn("results", body)
        text = json.dumps(body)
        self.assertNotIn("t-secret", text)
        self.assertNotIn("treatment", text)
        self.assertNotIn("clinical", text)

    def test_unsupported_media_type(self):
        status, payload = self.post(
            {"rules": [make_rule()], "transfers": [make_transfer()]},
            content_type="text/plain",
        )
        self.assertEqual(status, 415)
        self.assertEqual(payload["error"]["code"], "unsupported_media_type")

    def test_invalid_json(self):
        status, payload = self.post("{not json")
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"]["code"], "invalid_json")

    def test_method_not_allowed(self):
        for method in ("GET", "PUT", "DELETE", "PATCH"):
            with self.subTest(method=method):
                status, payload = self.request(method, PATH)
                self.assertEqual(status, 405)
                self.assertEqual(payload["error"]["code"], "method_not_allowed")

    def test_unknown_path_404(self):
        status, payload = self.request("POST", "/v1/compliance/transfer")
        self.assertEqual(status, 404)
        self.assertEqual(payload["error"]["code"], "not_found")


if __name__ == "__main__":
    unittest.main()
