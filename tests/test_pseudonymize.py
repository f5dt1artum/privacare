import copy
import http.client
import json
import re
import threading
import unittest
from http.server import ThreadingHTTPServer

from privacare.classifier import InvalidRequest
from privacare.pseudonymizer import (
    DEFAULT_CONTEXT,
    InvalidContext,
    InvalidFields,
    InvalidKey,
)
from privacare.server import Handler
from privacare.service import Service

SECRET_32 = "A" * 43  # base64url of 32 zero bytes
SECRET_31 = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHg"  # decodes to 31 bytes
GOLDEN_NAME_TOKEN = "e4hwa7kIHPwDQgG9a4HWpnMdVRUwAA56z0AP17mZlxQ"

TOKEN_RE = re.compile(r"^pv1\.k-1\.[A-Za-z0-9_-]{43}$")


def pseudonymize(payload):
    return Service().pseudonymize(payload)


def base_payload(**overrides):
    payload = {
        "records": [{"name": "张三", "contact": {"phone": "13800138000"}, "ids": ["a/b", "m~n"]}],
        "fields": ["/name", "/contact/phone", "/ids/0", "/ids/1"],
        "key_id": "k-1",
        "secret": SECRET_32,
    }
    payload.update(overrides)
    return payload


class PseudonymizeTest(unittest.TestCase):
    def test_happy_path_replaces_leaves_keeps_rest(self):
        [result] = pseudonymize(base_payload())
        self.assertEqual(result["index"], 0)
        record = result["record"]
        self.assertTrue(TOKEN_RE.fullmatch(record["name"]))
        self.assertTrue(TOKEN_RE.fullmatch(record["contact"]["phone"]))
        for value in record["ids"]:
            self.assertTrue(TOKEN_RE.fullmatch(value))
        # non-target content stays untouched
        self.assertEqual(set(record["contact"]), {"phone"})

    def test_golden_token_format_and_value(self):
        [result] = pseudonymize(base_payload())
        self.assertEqual(result["record"]["name"], f"pv1.k-1.{GOLDEN_NAME_TOKEN}")
        token = result["record"]["name"].split(".", 2)[2]
        self.assertEqual(len(token), 43)
        self.assertNotIn("=", token)
        self.assertNotIn("+", token)
        self.assertNotIn("/", token)

    def test_escape_sequences_tilde0_tilde1(self):
        payload = {
            "records": [{"a/b": {"m~n": "secret"}}],
            "fields": ["/a~1b/m~0n"],
            "key_id": "k-1",
            "secret": SECRET_32,
        }
        [result] = pseudonymize(payload)
        self.assertEqual(set(result["record"]["a/b"]), {"m~n"})
        self.assertTrue(TOKEN_RE.fullmatch(result["record"]["a/b"]["m~n"]))
        self.assertEqual(result["transformations"], [{"path": "/a~1b/m~0n", "key_id": "k-1"}])

    def test_results_follow_input_order(self):
        payload = base_payload(records=[{"name": "a"}, {"name": "b"}, {"note": "x"}])
        payload["fields"] = ["/name"]
        # third record has no /name -> request must fail as a whole
        with self.assertRaises(InvalidFields):
            pseudonymize(payload)
        payload = base_payload(records=[{"name": "a"}, {"name": "b"}, {"name": "c"}])
        payload["fields"] = ["/name"]
        results = pseudonymize(payload)
        self.assertEqual([r["index"] for r in results], [0, 1, 2])

    def test_transformations_sorted_with_only_path_and_key_id(self):
        [result] = pseudonymize(base_payload())
        paths = [t["path"] for t in result["transformations"]]
        self.assertEqual(paths, sorted(paths))
        self.assertEqual(
            paths,
            ["/contact/phone", "/ids/0", "/ids/1", "/name"],
        )
        for item in result["transformations"]:
            self.assertEqual(set(item), {"path", "key_id"})
            self.assertEqual(item["key_id"], "k-1")

    def test_deterministic_and_cross_record_linkage(self):
        payload = base_payload(
            records=[
                {"name": "张三", "phone": "13800138000"},
                {"name": "李四", "phone": "13800138000"},
                {"name": "张三", "phone": "13900139000"},
            ]
        )
        payload["fields"] = ["/name", "/phone"]
        r0, r1, r2 = pseudonymize(payload)
        # same value + same path links across records
        self.assertEqual(r0["record"]["name"], r2["record"]["name"])
        self.assertEqual(r0["record"]["phone"], r1["record"]["phone"])
        # different values at the same path diverge
        self.assertNotEqual(r0["record"]["name"], r1["record"]["name"])
        self.assertNotEqual(r0["record"]["phone"], r2["record"]["phone"])
        # same value at different paths diverges
        payload = base_payload(records=[{"a": "same", "b": "same"}])
        payload["fields"] = ["/a", "/b"]
        [r] = pseudonymize(payload)
        self.assertNotEqual(r["record"]["a"], r["record"]["b"])
        # identical requests, independent service instances
        self.assertEqual(Service().pseudonymize(payload), Service().pseudonymize(payload))

    def test_change_any_input_changes_token(self):
        base = base_payload(records=[{"name": "Alice"}])
        base["fields"] = ["/name"]
        baseline = pseudonymize(base)[0]["record"]["name"]

        def token(**overrides):
            return pseudonymize(base_payload(**overrides, records=[{"name": "Alice"}], fields=["/name"]))[0]["record"]["name"]

        self.assertNotEqual(baseline, token(secret="B" * 43))
        self.assertNotEqual(baseline, token(key_id="k-2"))
        self.assertNotEqual(baseline, token(context="other-context"))
        # different value diverges
        changed = pseudonymize(base_payload(records=[{"name": "Bob"}], fields=["/name"]))[0]["record"]["name"]
        self.assertNotEqual(baseline, changed)

    def test_context_defaults_and_explicit_equivalence(self):
        payload = base_payload(records=[{"name": "Alice"}], fields=["/name"])
        omitted = pseudonymize(payload)[0]["record"]["name"]
        explicit = pseudonymize(base_payload(records=[{"name": "Alice"}], fields=["/name"], context=DEFAULT_CONTEXT))[0]["record"]["name"]
        null_ctx = pseudonymize(base_payload(records=[{"name": "Alice"}], fields=["/name"], context=None))[0]["record"]["name"]
        self.assertEqual(omitted, explicit)
        self.assertEqual(omitted, null_ctx)

    def test_caller_data_not_mutated(self):
        payload = base_payload()
        snapshot = copy.deepcopy(payload)
        pseudonymize(payload)
        self.assertEqual(payload, snapshot)
        pseudonymize(payload)
        self.assertEqual(payload, snapshot)

    def test_response_does_not_echo_secret(self):
        payload = base_payload()
        blob = json.dumps(pseudonymize(payload))
        self.assertNotIn(SECRET_32, blob)
        self.assertNotIn("张三", blob)
        self.assertNotIn("13800138000", blob)

    def test_secret_length_boundary(self):
        # exactly 32 bytes is accepted
        pseudonymize(base_payload(secret=SECRET_32))
        # 33 bytes (base64url 44 chars) is accepted
        pseudonymize(base_payload(secret="A" * 44))
        # 31 bytes is rejected
        with self.assertRaises(InvalidKey):
            pseudonymize(base_payload(secret=SECRET_31))


class InvalidRequestTest(unittest.TestCase):
    def test_invalid_request(self):
        bad_payloads = [
            None,
            [],
            "x",
            42,
            {},
            {"fields": ["/name"], "key_id": "k-1", "secret": SECRET_32},
            {"records": [], "fields": ["/name"], "key_id": "k-1", "secret": SECRET_32},
            {"records": [1], "fields": ["/name"], "key_id": "k-1", "secret": SECRET_32},
            {"records": "x", "fields": ["/name"], "key_id": "k-1", "secret": SECRET_32},
        ]
        for payload in bad_payloads:
            with self.subTest(payload=payload):
                with self.assertRaises(InvalidRequest):
                    pseudonymize(payload)


class InvalidFieldsTest(unittest.TestCase):
    def test_bad_fields_arrays(self):
        for fields in (None, "x", 1, [], ["/name", "/name"], [""], ["name"], ["/name", 1]):
            with self.subTest(fields=fields):
                with self.assertRaises(InvalidFields):
                    pseudonymize(base_payload(fields=fields))

    def test_bad_pointer_syntax(self):
        for pointer in ("/a~2", "/a~", "/a~x"):
            with self.subTest(pointer=pointer):
                with self.assertRaises(InvalidFields):
                    pseudonymize(base_payload(fields=[pointer]))

    def test_path_missing_or_out_of_bounds(self):
        for pointer in ("/missing", "/contact/fax", "/ids/3", "/ids/-", "/ids/01", "/name/x"):
            with self.subTest(pointer=pointer):
                with self.assertRaises(InvalidFields):
                    pseudonymize(base_payload(fields=[pointer]))

    def test_target_must_be_non_empty_string_leaf(self):
        records = [
            {"n": 1},
            {"n": True},
            {"n": None},
            {"n": ["x"]},
            {"n": {"x": 1}},
            {"n": ""},
        ]
        for record in records:
            with self.subTest(record=record):
                with self.assertRaises(InvalidFields):
                    pseudonymize(base_payload(records=[record], fields=["/n"]))

    def test_failure_is_all_or_nothing_and_value_free(self):
        # second record lacks the target
        payload = base_payload(records=[{"name": "ok"}, {"other": "x"}])
        payload["fields"] = ["/name"]
        try:
            pseudonymize(payload)
        except InvalidFields as exc:
            self.assertNotIn("ok", str(exc))
        else:
            self.fail("expected InvalidFields")


class InvalidKeyTest(unittest.TestCase):
    def test_bad_key_id(self):
        for key_id in (None, "", 1, [], {}):
            with self.subTest(key_id=key_id):
                with self.assertRaises(InvalidKey):
                    pseudonymize(base_payload(key_id=key_id))

    def test_bad_secret(self):
        for secret in (
            None,
            "",
            1,
            "AAAA",  # 3 bytes
            SECRET_31,  # 31 bytes
            "A" * 42 + "=",  # padding is not allowed
            "A" * 42 + "+",  # padding char set not accepted
            "A" * 42 + " ",  # whitespace not accepted
            "A" * 45,  # length mod 4 == 1 is impossible in base64
        ):
            with self.subTest(secret=secret):
                with self.assertRaises(InvalidKey):
                    pseudonymize(base_payload(secret=secret))

    def test_key_errors_do_not_echo_secret(self):
        try:
            pseudonymize(base_payload(secret=SECRET_31))
        except InvalidKey as exc:
            self.assertNotIn(SECRET_31, str(exc))
        else:
            self.fail("expected InvalidKey")


class InvalidContextTest(unittest.TestCase):
    def test_bad_context(self):
        for context in ("", 1, True, [], {}):
            with self.subTest(context=context):
                with self.assertRaises(InvalidContext):
                    pseudonymize(base_payload(context=context))


class PseudonymizeHttpTest(unittest.TestCase):
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
        body = payload if isinstance(payload, (str, bytes)) else json.dumps(payload)
        return self.request("POST", "/v1/pseudonymize", body=body, content_type=content_type)

    def test_happy_path(self):
        status, payload, _ = self.post(base_payload())
        self.assertEqual(status, 200)
        [result] = payload["results"]
        self.assertEqual(result["record"]["name"], f"pv1.k-1.{GOLDEN_NAME_TOKEN}")
        blob = json.dumps(payload, ensure_ascii=False)
        self.assertNotIn("张三", blob)
        self.assertNotIn("13800138000", blob)
        self.assertNotIn(SECRET_32, blob)

    def test_method_not_allowed(self):
        for method in ("GET", "PUT", "DELETE", "PATCH"):
            with self.subTest(method=method):
                status, payload, allow = self.request(method, "/v1/pseudonymize")
                self.assertEqual(status, 405)
                self.assertEqual(payload["error"]["code"], "method_not_allowed")
                self.assertEqual(allow, "POST")

    def test_unknown_path_404(self):
        status, payload, _ = self.request("POST", "/v1/nope", body="{}", content_type="application/json")
        self.assertEqual(status, 404)
        self.assertEqual(payload["error"]["code"], "not_found")

    def test_unsupported_media_type(self):
        status, payload, _ = self.post(base_payload(), content_type="text/plain")
        self.assertEqual(status, 415)
        self.assertEqual(payload["error"]["code"], "unsupported_media_type")

    def test_invalid_json(self):
        status, payload, _ = self.post("{not json")
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"]["code"], "invalid_json")

    def test_error_codes(self):
        cases = [
            (base_payload(records=[]), "invalid_request"),
            (base_payload(fields=[]), "invalid_fields"),
            (base_payload(fields=["/missing"]), "invalid_fields"),
            (base_payload(key_id=""), "invalid_key"),
            (base_payload(secret=SECRET_31), "invalid_key"),
            (base_payload(context=""), "invalid_context"),
        ]
        for body, code in cases:
            with self.subTest(code=code):
                status, payload, _ = self.post(body)
                self.assertEqual(status, 422)
                self.assertEqual(payload["error"]["code"], code)

    def test_error_body_value_free(self):
        status, payload, _ = self.post(base_payload(secret="bad-secret"))
        self.assertEqual(status, 422)
        self.assertNotIn("bad-secret", json.dumps(payload))


if __name__ == "__main__":
    unittest.main()
