import base64
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
    pseudonymize_request,
)
from privacare.server import Handler
from privacare.service import Service

_TOKEN_RE = re.compile(r"^pv1\.[^.]+\.[A-Za-z0-9_-]{43}$")
_BASE64URL_TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{43}$")


def secret_of(nbytes: int = 32, offset: int = 0) -> str:
    raw = bytes((i + offset) % 256 for i in range(nbytes))
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


SECRET = secret_of()
KEY_ID = "k-2026-01"


def body(records, fields, key_id=KEY_ID, secret=SECRET, **extra):
    payload = {"records": records, "fields": fields, "key_id": key_id, "secret": secret}
    payload.update(extra)
    return payload


def run(payload):
    return Service().pseudonymize(payload)


class PseudonymizeHappyPathTest(unittest.TestCase):
    def test_response_shape_and_token_format(self):
        records = [
            {"patient": {"name": "张三"}, "ids": ["P-001", "P-002"]},
            {"patient": {"name": "李四"}, "ids": ["P-003", "P-002"]},
        ]
        fields = ["/patient/name", "/ids/0", "/ids/1"]
        results = run(body(records, fields))
        self.assertEqual([r["index"] for r in results], [0, 1])
        for result in results:
            self.assertEqual(set(result), {"index", "record", "transformations"})
            self.assertEqual(
                [t["path"] for t in result["transformations"]],
                sorted(fields),
            )
            for t in result["transformations"]:
                self.assertEqual(set(t), {"path", "key_id"})
                self.assertEqual(t["key_id"], KEY_ID)
        for result in results:
            pseudonyms = (
                result["record"]["patient"]["name"],
                result["record"]["ids"][0],
                result["record"]["ids"][1],
            )
            for value in pseudonyms:
                self.assertRegex(value, _TOKEN_RE)
                token = value.rsplit(".", 1)[1]
                self.assertRegex(token, _BASE64URL_TOKEN_RE)
                decoded = base64.urlsafe_b64decode(token + "=")
                self.assertEqual(len(decoded), 32)

    def test_pseudonym_structure_uses_key_id(self):
        results = run(body([{"a": "v"}], ["/a"], key_id="ver-9"))
        value = results[0]["record"]["a"]
        self.assertTrue(value.startswith("pv1.ver-9."))

    def test_same_value_same_path_links_across_records(self):
        records = [{"a": "MRN-1"}, {"a": "MRN-1"}, {"a": "MRN-2"}]
        results = run(body(records, ["/a"]))
        tokens = [r["record"]["a"] for r in results]
        self.assertEqual(tokens[0], tokens[1])
        self.assertNotEqual(tokens[0], tokens[2])

    def test_same_value_different_paths_get_different_tokens(self):
        records = [{"a": "same", "b": "same"}]
        results = run(body(records, ["/a", "/b"]))
        self.assertNotEqual(results[0]["record"]["a"], results[0]["record"]["b"])

    def test_changing_any_input_changes_token(self):
        records = [{"a": "v"}]
        base = run(body(records, ["/a"]))[0]["record"]["a"]
        cases = [
            (body(records, ["/a"], secret=secret_of(offset=1)), "a"),
            (body(records, ["/a"], key_id="other-key"), "a"),
            (body(records, ["/a"], context="other-context"), "a"),
            (body([{"a": "w"}], ["/a"]), "a"),
            # Same original value reached through a different normalized path
            (body([{"x": "v"}], ["/x"]), "x"),
        ]
        for payload, key in cases:
            with self.subTest(key=key):
                self.assertNotEqual(run(payload)[0]["record"][key], base)

    def test_default_context_is_fixed_and_explicit_default_matches(self):
        records = [{"a": "v"}]
        omitted = run(body(records, ["/a"]))[0]["record"]["a"]
        explicit = run(body(records, ["/a"], context=DEFAULT_CONTEXT))[0]["record"]["a"]
        self.assertEqual(omitted, explicit)
        other = run(body(records, ["/a"], context="else"))[0]["record"]["a"]
        self.assertNotEqual(omitted, other)

    def test_escaped_pointer_segments(self):
        records = [{"a/b": "v1", "m~n": "v2"}]
        results = run(body(records, ["/a~1b", "/m~0n"]))
        record = results[0]["record"]
        self.assertRegex(record["a/b"], _TOKEN_RE)
        self.assertRegex(record["m~n"], _TOKEN_RE)
        self.assertEqual(
            [t["path"] for t in results[0]["transformations"]],
            ["/a~1b", "/m~0n"],
        )

    def test_nested_objects_arrays_and_empty_key(self):
        records = [
            {"": "root-empty", "xs": [{"k": "deep-0"}, {"k": "deep-1"}]},
            {"": "root-empty", "xs": [{"k": "deep-0"}, {"k": "other"}]},
        ]
        fields = ["/", "/xs/0/k", "/xs/1/k"]
        results = run(body(records, fields))
        self.assertEqual(results[0]["record"][""], results[1]["record"][""])
        self.assertEqual(
            results[0]["record"]["xs"][0]["k"], results[1]["record"]["xs"][0]["k"]
        )
        self.assertNotEqual(
            results[0]["record"]["xs"][1]["k"], results[1]["record"]["xs"][1]["k"]
        )

    def test_non_target_content_is_unchanged(self):
        records = [
            {"id": "P-1", "age": 41, "tags": ["x", None], "meta": {"keep": "原样"}},
        ]
        results = run(body(records, ["/id"]))
        record = results[0]["record"]
        self.assertEqual(record["age"], 41)
        self.assertEqual(record["tags"], ["x", None])
        self.assertEqual(record["meta"], {"keep": "原样"})
        self.assertRegex(record["id"], _TOKEN_RE)

    def test_transformations_sorted_by_path(self):
        fields = ["/z", "/a/0", "/a/1", "/m"]
        records = [{"z": "1", "a": ["2", "3"], "m": "4"}]
        results = run(body(records, fields))
        self.assertEqual(
            [t["path"] for t in results[0]["transformations"]],
            ["/a/0", "/a/1", "/m", "/z"],
        )

    def test_deterministic_and_input_not_mutated(self):
        payload = body(
            [
                {"id": "P-1", "nested": {"id": "P-2"}},
                {"id": "P-1", "nested": {"id": "P-2"}},
            ],
            ["/id", "/nested/id"],
        )
        snapshot = copy.deepcopy(payload)
        first = run(payload)
        second = run(copy.deepcopy(payload))
        self.assertEqual(first, second)
        self.assertEqual(payload, snapshot)
        # The returned records are copies, not aliases.
        first[0]["record"]["id"] = "tampered"
        self.assertEqual(run(payload)[0]["record"]["id"], second[0]["record"]["id"])

    def test_response_does_not_echo_values_or_secret(self):
        secret_value = "top-secret-value-患者"
        payload = body(
            [{"a": secret_value}, {"a": secret_value + "-2"}],
            ["/a"],
            secret=SECRET,
        )
        blob = json.dumps(run(payload), ensure_ascii=False)
        self.assertNotIn(secret_value, blob)
        self.assertNotIn(secret_value + "-2", blob)
        self.assertNotIn(SECRET, blob)


class FieldsValidationTest(unittest.TestCase):
    def test_fields_must_be_non_empty_array_of_strings(self):
        good_records = [{"a": "x"}]
        for fields in (None, [], "x", 1, ["/a", 1], [None], ["/a", "/a"]):
            with self.subTest(fields=fields):
                with self.assertRaises(InvalidFields):
                    run(body(good_records, fields))

    def test_missing_fields_is_invalid_fields(self):
        with self.assertRaises(InvalidFields):
            run({"records": [{"a": "x"}], "key_id": KEY_ID, "secret": SECRET})

    def test_invalid_pointer_syntax(self):
        for pointer in ("a", "/a~2", "/a~"):
            with self.subTest(pointer=pointer):
                with self.assertRaises(InvalidFields):
                    run(body([{"a": "x"}], [pointer]))

    def test_resolution_failures(self):
        cases = [
            ([{"a": "x"}], ["/b"]),                          # missing key
            ([{"a": "x"}], ["/a/x"]),                        # descent into scalar
            ([{"xs": ["x"]}], ["/xs/2"]),                    # array out of bounds
            ([{"xs": ["x"]}], ["/xs/-"]),                    # "-" never resolves
            ([{"xs": ["x"]}], ["/xs/01"]),                   # leading zero
            ([{"a": {"b": "x"}}], ["/a"]),                   # object container
            ([{"a": ["x"]}], ["/a"]),                        # array container
            ([{"a": 1}], ["/a"]),                            # number
            ([{"a": True}], ["/a"]),                         # boolean
            ([{"a": None}], ["/a"]),                         # null
            ([{"a": ""}], ["/a"]),                           # empty string
            ([{"a": "x"}, {"b": "x"}], ["/a"]),              # missing on one record
        ]
        for records, fields in cases:
            with self.subTest(fields=fields):
                with self.assertRaises(InvalidFields):
                    run(body(records, fields))

    def test_empty_key_pointer_is_valid(self):
        results = run(body([{"": "x"}], ["/"]))
        self.assertRegex(results[0]["record"][""], _TOKEN_RE)


class KeyValidationTest(unittest.TestCase):
    def test_invalid_key_id(self):
        for key_id in (None, "", 1, [], True):
            with self.subTest(key_id=key_id):
                with self.assertRaises(InvalidKey):
                    run(body([{"a": "x"}], ["/a"], key_id=key_id))

    def test_missing_key_id(self):
        with self.assertRaises(InvalidKey):
            run({"records": [{"a": "x"}], "fields": ["/a"], "secret": SECRET})

    def test_invalid_secret(self):
        short = base64.urlsafe_b64encode(b"x" * 31).rstrip(b"=").decode()
        exactly_32 = base64.urlsafe_b64encode(b"x" * 32).rstrip(b"=").decode()
        for secret in (
            None,
            "",
            123,
            short,
            exactly_32[:-1] + "=",          # padding present
            "abc$def",                       # illegal alphabet
            "A",                             # far too short
        ):
            with self.subTest(secret=secret):
                with self.assertRaises(InvalidKey):
                    run(body([{"a": "x"}], ["/a"], secret=secret))

    def test_secret_shorter_than_32_bytes_rejected(self):
        with self.assertRaises(InvalidKey):
            run(body([{"a": "x"}], ["/a"], secret=secret_of(31)))

    def test_secret_longer_than_32_bytes_accepted(self):
        results = run(body([{"a": "x"}], ["/a"], secret=secret_of(64)))
        self.assertRegex(results[0]["record"]["a"], _TOKEN_RE)

    def test_missing_secret(self):
        with self.assertRaises(InvalidKey):
            run({"records": [{"a": "x"}], "fields": ["/a"], "key_id": KEY_ID})


class ContextValidationTest(unittest.TestCase):
    def test_invalid_context(self):
        for context in ("", 1, [], True, {}):
            with self.subTest(context=context):
                with self.assertRaises(InvalidContext):
                    run(body([{"a": "x"}], ["/a"], context=context))


class RequestShapeValidationTest(unittest.TestCase):
    def test_invalid_request(self):
        good_fields = ["/a"]
        for payload in (
            None,
            [],
            "x",
            {},
            {"fields": good_fields, "key_id": KEY_ID, "secret": SECRET},
            {"records": [], "fields": good_fields, "key_id": KEY_ID, "secret": SECRET},
            {"records": [1], "fields": good_fields, "key_id": KEY_ID, "secret": SECRET},
            {"records": ["s"], "fields": good_fields, "key_id": KEY_ID, "secret": SECRET},
        ):
            with self.subTest(payload=payload):
                with self.assertRaises(InvalidRequest):
                    run(payload)

    def test_records_validated_before_fields(self):
        with self.assertRaises(InvalidRequest):
            run({"records": [1], "fields": ["/missing"], "key_id": KEY_ID, "secret": SECRET})

    def test_no_partial_results_or_mutations(self):
        records = [{"a": "ok"}, {"a": 1}]
        snapshot = copy.deepcopy(records)
        with self.assertRaises(InvalidFields):
            run(body(records, ["/a"]))
        self.assertEqual(records, snapshot)


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

    def request(self, method, path, body_bytes=None, content_type=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        headers = {}
        if content_type is not None:
            headers["Content-Type"] = content_type
        conn.request(method, path, body=body_bytes, headers=headers)
        resp = conn.getresponse()
        raw = resp.read()
        allow = resp.getheader("Allow")
        conn.close()
        return resp.status, json.loads(raw), allow

    def post(self, payload, content_type="application/json"):
        raw = payload if isinstance(payload, (str, bytes)) else json.dumps(payload)
        return self.request("POST", "/v1/pseudonymize", body_bytes=raw, content_type=content_type)

    def test_happy_path(self):
        status, payload, _ = self.post(
            {"records": [{"a": "v"}, {"a": "v"}], "fields": ["/a"],
             "key_id": KEY_ID, "secret": SECRET}
        )
        self.assertEqual(status, 200)
        self.assertEqual(set(payload), {"results"})
        results = payload["results"]
        self.assertEqual(results[0]["record"]["a"], results[1]["record"]["a"])
        self.assertRegex(results[0]["record"]["a"], _TOKEN_RE)

    def test_method_not_allowed(self):
        for method in ("GET", "PUT", "DELETE", "PATCH"):
            with self.subTest(method=method):
                status, payload, allow = self.request(method, "/v1/pseudonymize")
                self.assertEqual(status, 405)
                self.assertEqual(payload["error"]["code"], "method_not_allowed")
                self.assertEqual(allow, "POST")

    def test_unknown_path_404(self):
        for method, path in (("POST", "/v1/nope"), ("GET", "/nope")):
            with self.subTest(method=method, path=path):
                status, payload, _ = self.request(method, path)
                self.assertEqual(status, 404)
                self.assertEqual(payload["error"]["code"], "not_found")

    def test_unsupported_media_type(self):
        status, payload, _ = self.post(json.dumps({"records": [{}]}), content_type="text/plain")
        self.assertEqual(status, 415)
        self.assertEqual(payload["error"]["code"], "unsupported_media_type")

    def test_missing_content_type(self):
        status, payload, _ = self.request(
            "POST", "/v1/pseudonymize", body_bytes="{}"
        )
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
                {"records": [], "fields": ["/a"], "key_id": KEY_ID, "secret": SECRET},
            ),
            (
                "invalid_fields",
                {"records": [{"a": "x"}], "fields": ["/b"], "key_id": KEY_ID, "secret": SECRET},
            ),
            (
                "invalid_key",
                {"records": [{"a": "x"}], "fields": ["/a"], "key_id": KEY_ID, "secret": "AAAA"},
            ),
            (
                "invalid_context",
                {"records": [{"a": "x"}], "fields": ["/a"], "key_id": KEY_ID,
                 "secret": SECRET, "context": ""},
            ),
        ]
        for code, payload in cases:
            with self.subTest(code=code):
                status, parsed, _ = self.post(payload)
                self.assertEqual(status, 422)
                self.assertEqual(parsed["error"]["code"], code)
                self.assertNotIn("results", parsed)

    def test_error_body_does_not_echo_secret_or_value(self):
        status, payload, _ = self.post(
            {"records": [{"a": "PATIENT-SECRET"}], "fields": ["/missing"],
             "key_id": KEY_ID, "secret": SECRET}
        )
        self.assertEqual(status, 422)
        blob = json.dumps(payload, ensure_ascii=False)
        self.assertNotIn("PATIENT-SECRET", blob)
        self.assertNotIn(SECRET, blob)


if __name__ == "__main__":
    unittest.main()
