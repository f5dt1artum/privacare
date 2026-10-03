import base64
import copy
import http.client
import json
import threading
import unittest
from http.server import ThreadingHTTPServer

from privacare.classifier import InvalidRequest
from privacare.encryption import (
    ALG,
    DEFAULT_CONTEXT,
    InvalidCiphertext,
    InvalidEnvelope,
    _aes_gcm_encrypt,
    _expand_key,
    _aes_encrypt_block,
)
from privacare.pseudonymizer import InvalidContext, InvalidFields, InvalidKey
from privacare.server import Handler
from privacare.service import Service

SECRET_32 = "A" * 43  # base64url of 32 zero bytes
SECRET_32_B = "B" * 43
SECRET_31 = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHg"  # decodes to 31 bytes
SECRET_33 = "A" * 44  # decodes to 33 bytes

ENVELOPE_KEYS = {"alg", "key_id", "context", "nonce", "ciphertext"}


def encrypt(payload):
    return Service().encrypt(payload)


def decrypt(payload):
    return Service().decrypt(payload)


def rotate(payload):
    return Service().rotate_encryption(payload)


def base_payload(**overrides):
    payload = {
        "records": [
            {"name": "张三", "contact": {"phone": "13800138000"}, "ids": ["a/b", "m~n"]}
        ],
        "fields": ["/name", "/contact/phone", "/ids/0", "/ids/1"],
        "key_id": "k-1",
        "secret": SECRET_32,
    }
    payload.update(overrides)
    return payload


def encrypt_one(record, fields, **overrides):
    payload = {"records": [record], "fields": fields, "key_id": "k-1", "secret": SECRET_32}
    payload.update(overrides)
    return encrypt(payload)[0]["record"]


def decrypt_payload(records, fields, **overrides):
    payload = {"records": records, "fields": fields, "keys": {"k-1": SECRET_32}}
    payload.update(overrides)
    return payload


class AesGcmVectorTest(unittest.TestCase):
    def test_aes256_fips197_vector(self):
        key = bytes.fromhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
        block = bytes.fromhex("00112233445566778899aabbccddeeff")
        self.assertEqual(
            _aes_encrypt_block(_expand_key(key), block).hex(),
            "8ea2b7ca516745bfeafc49904b496089",
        )

    def test_gcm_nist_vector_no_aad(self):
        sealed = _aes_gcm_encrypt(bytes(32), bytes(12), bytes(16), b"")
        self.assertEqual(
            sealed.hex(),
            "cea7403d4d606b6e074ec5d3baf39d18d0d1c8a799996bf0265b98b5d48ab919",
        )

    def test_gcm_nist_vector_with_aad(self):
        key = bytes.fromhex("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308")
        iv = bytes.fromhex("cafebabefacedbaddecaf888")
        aad = bytes.fromhex("feedfacedeadbeeffeedfacedeadbeefabaddad2")
        plaintext = bytes.fromhex(
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
            "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39"
        )
        sealed = _aes_gcm_encrypt(key, iv, plaintext, aad)
        self.assertEqual(
            sealed[: len(plaintext)].hex(),
            "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa"
            "8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662",
        )
        self.assertEqual(sealed[len(plaintext):].hex(), "76fc6ece0f4e1768cddf8853bb2d551b")


class EncryptTest(unittest.TestCase):
    def test_envelope_shape_and_encodings(self):
        [result] = encrypt(base_payload())
        envelope = result["record"]["name"]
        self.assertEqual(set(envelope), ENVELOPE_KEYS)
        self.assertEqual(envelope["alg"], ALG)
        self.assertEqual(envelope["key_id"], "k-1")
        self.assertEqual(envelope["context"], DEFAULT_CONTEXT)
        nonce = base64.urlsafe_b64decode(envelope["nonce"] + "==")
        self.assertEqual(len(nonce), 12)
        sealed = base64.urlsafe_b64decode(envelope["ciphertext"] + "==")
        self.assertGreaterEqual(len(sealed), 16)
        for value in (envelope["nonce"], envelope["ciphertext"]):
            self.assertNotIn("=", value)
            self.assertNotIn("+", value)
            self.assertNotIn("/", value)

    def test_nonce_is_random_per_encryption(self):
        first = encrypt(base_payload())[0]["record"]["name"]
        second = encrypt(base_payload())[0]["record"]["name"]
        self.assertNotEqual(first["nonce"], second["nonce"])
        self.assertNotEqual(first["ciphertext"], second["ciphertext"])

    def test_non_target_content_untouched(self):
        [result] = encrypt(base_payload())
        record = result["record"]
        self.assertEqual(set(record), {"name", "contact", "ids"})
        self.assertEqual(set(record["contact"]), {"phone"})
        self.assertEqual(len(record["ids"]), 2)

    def test_transformations_sorted_with_only_path_and_key_id(self):
        [result] = encrypt(base_payload())
        transformations = result["transformations"]
        paths = [t["path"] for t in transformations]
        self.assertEqual(paths, ["/contact/phone", "/ids/0", "/ids/1", "/name"])
        for item in transformations:
            self.assertEqual(set(item), {"path", "key_id"})
            self.assertEqual(item["key_id"], "k-1")

    def test_results_follow_input_order(self):
        payload = base_payload(records=[{"name": "a"}, {"name": "b"}, {"name": "c"}])
        payload["fields"] = ["/name"]
        results = encrypt(payload)
        self.assertEqual([r["index"] for r in results], [0, 1, 2])

    def test_escape_sequences_tilde0_tilde1(self):
        record = encrypt_one({"a/b": {"m~n": "secret"}}, ["/a~1b/m~0n"])
        self.assertEqual(set(record["a/b"]), {"m~n"})
        self.assertEqual(set(record["a/b"]["m~n"]), ENVELOPE_KEYS)

    def test_context_defaults_and_explicit_equivalence(self):
        omitted = encrypt_one({"name": "Alice"}, ["/name"])["name"]
        explicit = encrypt_one({"name": "Alice"}, ["/name"], context=DEFAULT_CONTEXT)["name"]
        null_ctx = encrypt_one({"name": "Alice"}, ["/name"], context=None)["name"]
        for envelope in (omitted, explicit, null_ctx):
            self.assertEqual(envelope["context"], DEFAULT_CONTEXT)
        # explicit default context decrypts under the same AAD
        [result] = decrypt(
            decrypt_payload([{"name": omitted}], ["/name"], keys={"k-1": SECRET_32})
        )
        self.assertEqual(result["record"]["name"], "Alice")

    def test_caller_data_not_mutated(self):
        payload = base_payload()
        snapshot = copy.deepcopy(payload)
        encrypt(payload)
        self.assertEqual(payload, snapshot)

    def test_response_does_not_echo_secret_or_values(self):
        blob = json.dumps(encrypt(base_payload()), ensure_ascii=False)
        self.assertNotIn(SECRET_32, blob)
        self.assertNotIn("张三", blob)
        self.assertNotIn("13800138000", blob)


class RoundTripTest(unittest.TestCase):
    def round_trip(self, record, fields):
        [encrypted] = encrypt(
            {"records": [record], "fields": fields, "key_id": "k-1", "secret": SECRET_32}
        )
        [decrypted] = decrypt(
            decrypt_payload([encrypted["record"]], fields)
        )
        return decrypted

    def test_all_json_value_types(self):
        record = {
            "s": "张三",
            "n": 42,
            "f": 1.5,
            "b": True,
            "z": None,
            "o": {"a": [1, "x", None]},
            "a": [1, 2, 3],
        }
        fields = ["/s", "/n", "/f", "/b", "/z", "/o", "/a"]
        result = self.round_trip(record, fields)
        self.assertEqual(result["record"], record)
        transformations = result["transformations"]
        self.assertEqual([t["path"] for t in transformations], sorted(fields))
        for item in transformations:
            self.assertEqual(set(item), {"path", "key_id"})
            self.assertEqual(item["key_id"], "k-1")

    def test_multi_record_round_trip(self):
        records = [{"name": "a"}, {"name": "b", "extra": 1}]
        fields = ["/name"]
        encrypted = encrypt(
            {"records": records, "fields": fields, "key_id": "k-1", "secret": SECRET_32}
        )
        decrypted = decrypt(
            decrypt_payload([r["record"] for r in encrypted], fields)
        )
        self.assertEqual([r["record"] for r in decrypted], records)
        self.assertEqual([r["index"] for r in decrypted], [0, 1])

    def test_decrypt_does_not_mutate_input(self):
        [encrypted] = encrypt(base_payload())
        payload = decrypt_payload([encrypted["record"]], ["/name", "/contact/phone", "/ids/0", "/ids/1"])
        snapshot = copy.deepcopy(payload)
        decrypt(payload)
        self.assertEqual(payload, snapshot)


class DecryptErrorTest(unittest.TestCase):
    def encrypted_record(self, record=None, fields=("/name",), **overrides):
        record = record if record is not None else {"name": "Alice", "other": "x"}
        return encrypt_one(record, list(fields), **overrides)

    def test_wrong_secret_is_invalid_ciphertext(self):
        record = self.encrypted_record()
        with self.assertRaises(InvalidCiphertext):
            decrypt(decrypt_payload([record], ["/name"], keys={"k-1": SECRET_32_B}))

    def test_moved_envelope_is_invalid_ciphertext(self):
        record = self.encrypted_record({"a": "same", "b": "same"}, ["/a", "/b"])
        record["a"], record["b"] = record["b"], record["a"]
        with self.assertRaises(InvalidCiphertext):
            decrypt(decrypt_payload([record], ["/a", "/b"]))

    def test_tampered_ciphertext_is_invalid_ciphertext(self):
        for mutate in ("ciphertext", "nonce", "context", "key_id"):
            with self.subTest(mutate=mutate):
                record = self.encrypted_record()
                envelope = dict(record["name"])
                if mutate == "ciphertext":
                    raw = bytearray(base64.urlsafe_b64decode(envelope["ciphertext"] + "=="))
                    raw[0] ^= 1
                    envelope["ciphertext"] = base64.urlsafe_b64encode(bytes(raw)).rstrip(b"=").decode()
                elif mutate == "nonce":
                    envelope["nonce"] = base64.urlsafe_b64encode(b"\x01" * 12).rstrip(b"=").decode()
                elif mutate == "context":
                    envelope["context"] = "other-context"
                else:
                    envelope["key_id"] = "k-1"  # keep id, tamper via context of another envelope
                    envelope["context"] = DEFAULT_CONTEXT + "x"
                record["name"] = envelope
                with self.assertRaises(InvalidCiphertext):
                    decrypt(decrypt_payload([record], ["/name"]))

    def test_missing_key_is_invalid_key(self):
        record = self.encrypted_record()
        with self.assertRaises(InvalidKey):
            decrypt(decrypt_payload([record], ["/name"], keys={"other": SECRET_32}))

    def test_bad_envelope_is_invalid_envelope(self):
        record = self.encrypted_record()
        good = record["name"]
        bad_envelopes = [
            None,
            "x",
            {},
            {k: v for k, v in good.items() if k != "nonce"},
            dict(good, extra="x"),
            dict(good, alg="A128GCM"),
            dict(good, key_id=""),
            dict(good, context=""),
            dict(good, nonce="!!!"),
            dict(good, nonce=base64.urlsafe_b64encode(b"\x00" * 11).rstrip(b"=").decode()),
            dict(good, ciphertext="A"),  # too short for a tag
            dict(good, ciphertext="not*base64url"),
        ]
        for envelope in bad_envelopes:
            with self.subTest(envelope=envelope):
                with self.assertRaises(InvalidEnvelope):
                    decrypt(decrypt_payload([{"name": envelope}], ["/name"]))

    def test_error_does_not_echo_secret_or_values(self):
        record = self.encrypted_record()
        try:
            decrypt(decrypt_payload([record], ["/name"], keys={"k-1": SECRET_32_B}))
        except InvalidCiphertext as exc:
            self.assertNotIn(SECRET_32_B, str(exc))
            self.assertNotIn("Alice", str(exc))
        else:
            self.fail("expected InvalidCiphertext")


class RotateTest(unittest.TestCase):
    def encrypt_records(self, records, fields, **overrides):
        payload = {"records": records, "fields": fields, "key_id": "k-1", "secret": SECRET_32}
        payload.update(overrides)
        return [r["record"] for r in encrypt(payload)]

    def rotate_payload(self, records, fields, **overrides):
        payload = {
            "records": records,
            "fields": fields,
            "keys": {"k-1": SECRET_32},
            "new_key_id": "k-2",
            "new_secret": SECRET_32_B,
        }
        payload.update(overrides)
        return payload

    def test_rotate_round_trip(self):
        records = [{"name": "张三", "n": 7}, {"name": "李四", "n": 8}]
        fields = ["/name", "/n"]
        encrypted = self.encrypt_records(records, fields)
        results = rotate(self.rotate_payload(encrypted, fields))
        self.assertEqual([r["index"] for r in results], [0, 1])
        for result, original in zip(results, records):
            envelope = result["record"]["name"]
            self.assertEqual(set(envelope), ENVELOPE_KEYS)
            self.assertEqual(envelope["key_id"], "k-2")
            self.assertEqual(envelope["context"], DEFAULT_CONTEXT)
            # new key opens the rotated envelope and restores the value
        rotated_records = [r["record"] for r in results]
        decrypted = decrypt(
            decrypt_payload(rotated_records, fields, keys={"k-2": SECRET_32_B})
        )
        self.assertEqual([r["record"] for r in decrypted], records)
        # the old key no longer opens rotated envelopes
        with self.assertRaises(InvalidCiphertext):
            decrypt(decrypt_payload(rotated_records, fields, keys={"k-2": SECRET_32}))

    def test_rotate_preserves_each_envelope_context(self):
        encrypted = self.encrypt_records([{"name": "Alice"}], ["/name"], context="ctx-a")
        [result] = rotate(self.rotate_payload(encrypted, ["/name"]))
        self.assertEqual(result["record"]["name"]["context"], "ctx-a")

    def test_rotate_transformations(self):
        encrypted = self.encrypt_records([{"b": 1, "a": 2}], ["/a", "/b"])
        [result] = rotate(self.rotate_payload(encrypted, ["/a", "/b"]))
        transformations = result["transformations"]
        self.assertEqual([t["path"] for t in transformations], ["/a", "/b"])
        for item in transformations:
            self.assertEqual(set(item), {"path", "old_key_id", "new_key_id"})
            self.assertEqual(item["old_key_id"], "k-1")
            self.assertEqual(item["new_key_id"], "k-2")

    def test_rotate_is_all_or_nothing(self):
        good, tampered = self.encrypt_records([{"name": "a"}, {"name": "b"}], ["/name"])
        raw = bytearray(base64.urlsafe_b64decode(tampered["name"]["ciphertext"] + "=="))
        raw[-1] ^= 1
        tampered["name"]["ciphertext"] = base64.urlsafe_b64encode(bytes(raw)).rstrip(b"=").decode()
        with self.assertRaises(InvalidCiphertext):
            rotate(self.rotate_payload([good, tampered], ["/name"]))

    def test_rotate_missing_old_key_is_invalid_key(self):
        encrypted = self.encrypt_records([{"name": "a"}], ["/name"])
        with self.assertRaises(InvalidKey):
            rotate(self.rotate_payload(encrypted, ["/name"], keys={"other": SECRET_32}))

    def test_rotate_bad_new_key_material(self):
        encrypted = self.encrypt_records([{"name": "a"}], ["/name"])
        for overrides in ({"new_key_id": ""}, {"new_key_id": 1}, {"new_secret": SECRET_31}, {"new_secret": None}):
            with self.subTest(overrides=overrides):
                with self.assertRaises(InvalidKey):
                    rotate(self.rotate_payload(encrypted, ["/name"], **overrides))

    def test_rotate_response_does_not_echo_secrets_or_values(self):
        encrypted = self.encrypt_records([{"name": "张三"}], ["/name"])
        blob = json.dumps(rotate(self.rotate_payload(encrypted, ["/name"])), ensure_ascii=False)
        self.assertNotIn(SECRET_32, blob)
        self.assertNotIn(SECRET_32_B, blob)
        self.assertNotIn("张三", blob)


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
                    encrypt(payload)
                with self.assertRaises(InvalidRequest):
                    decrypt(payload)
                with self.assertRaises(InvalidRequest):
                    rotate(payload)


class InvalidFieldsTest(unittest.TestCase):
    def test_bad_fields_arrays(self):
        for fields in (None, "x", 1, [], ["/name", "/name"], [""], ["name"], ["/name", 1]):
            with self.subTest(fields=fields):
                with self.assertRaises(InvalidFields):
                    encrypt(base_payload(fields=fields))

    def test_root_pointer_rejected(self):
        with self.assertRaises(InvalidFields):
            encrypt(base_payload(fields=[""]))

    def test_bad_pointer_syntax(self):
        for pointer in ("/a~2", "/a~", "/a~x"):
            with self.subTest(pointer=pointer):
                with self.assertRaises(InvalidFields):
                    encrypt(base_payload(fields=[pointer]))

    def test_overlapping_pointers_rejected(self):
        for fields in (
            ["/a", "/a/b"],
            ["/a/b", "/a"],
            ["/a", "/a"],
            ["/ids", "/ids/0"],
            ["/contact/phone", "/contact"],
        ):
            with self.subTest(fields=fields):
                with self.assertRaises(InvalidFields):
                    encrypt(base_payload(fields=fields))

    def test_sibling_pointers_accepted(self):
        encrypt(base_payload(fields=["/contact", "/name"]))
        encrypt(base_payload(fields=["/ids/0", "/ids/1"]))

    def test_path_missing_or_out_of_bounds(self):
        for pointer in ("/missing", "/contact/fax", "/ids/2", "/ids/-", "/ids/01", "/name/x"):
            with self.subTest(pointer=pointer):
                with self.assertRaises(InvalidFields):
                    encrypt(base_payload(fields=[pointer]))

    def test_any_json_value_may_be_targeted(self):
        for value in (None, True, 1, 1.5, "", [], {}, {"x": 1}, ["x"]):
            with self.subTest(value=value):
                [result] = encrypt(base_payload(records=[{"n": value}], fields=["/n"]))
                self.assertEqual(set(result["record"]["n"]), ENVELOPE_KEYS)


class InvalidKeyAndContextTest(unittest.TestCase):
    def test_bad_key_id(self):
        for key_id in (None, "", 1, [], {}):
            with self.subTest(key_id=key_id):
                with self.assertRaises(InvalidKey):
                    encrypt(base_payload(key_id=key_id))

    def test_secret_must_decode_to_exactly_32_bytes(self):
        encrypt(base_payload(secret=SECRET_32))
        for secret in (
            None,
            "",
            1,
            "AAAA",
            SECRET_31,
            SECRET_33,
            "A" * 42 + "=",
            "A" * 42 + "+",
            "A" * 45,
        ):
            with self.subTest(secret=secret):
                with self.assertRaises(InvalidKey):
                    encrypt(base_payload(secret=secret))

    def test_bad_keys_map(self):
        for keys in (None, {}, "x", [], {"": SECRET_32}, {"k-1": SECRET_31}, {"k-1": "nope"}):
            with self.subTest(keys=keys):
                with self.assertRaises(InvalidKey):
                    decrypt(decrypt_payload([{"name": "x"}], ["/name"], keys=keys))

    def test_bad_context(self):
        for context in ("", 1, True, [], {}):
            with self.subTest(context=context):
                with self.assertRaises(InvalidContext):
                    encrypt(base_payload(context=context))

    def test_key_errors_do_not_echo_secret(self):
        try:
            encrypt(base_payload(secret=SECRET_31))
        except InvalidKey as exc:
            self.assertNotIn(SECRET_31, str(exc))
        else:
            self.fail("expected InvalidKey")


class EncryptionHttpTest(unittest.TestCase):
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

    def post(self, path, payload, content_type="application/json"):
        body = payload if isinstance(payload, (str, bytes)) else json.dumps(payload)
        return self.request("POST", path, body=body, content_type=content_type)

    def test_encrypt_decrypt_rotate_over_http(self):
        status, payload, _ = self.post("/v1/encryption/encrypt", base_payload())
        self.assertEqual(status, 200)
        [result] = payload["results"]
        self.assertEqual(set(result["record"]["name"]), ENVELOPE_KEYS)
        blob = json.dumps(payload, ensure_ascii=False)
        self.assertNotIn("张三", blob)
        self.assertNotIn(SECRET_32, blob)

        records = [result["record"]]
        fields = ["/name", "/contact/phone", "/ids/0", "/ids/1"]
        status, payload, _ = self.post(
            "/v1/encryption/decrypt", decrypt_payload(records, fields)
        )
        self.assertEqual(status, 200)
        self.assertEqual(
            payload["results"][0]["record"],
            {"name": "张三", "contact": {"phone": "13800138000"}, "ids": ["a/b", "m~n"]},
        )

        status, payload, _ = self.post(
            "/v1/encryption/rotate",
            {
                "records": records,
                "fields": fields,
                "keys": {"k-1": SECRET_32},
                "new_key_id": "k-2",
                "new_secret": SECRET_32_B,
            },
        )
        self.assertEqual(status, 200)
        rotated = payload["results"][0]["record"]
        self.assertEqual(rotated["name"]["key_id"], "k-2")
        status, payload, _ = self.post(
            "/v1/encryption/decrypt",
            decrypt_payload([rotated], fields, keys={"k-2": SECRET_32_B}),
        )
        self.assertEqual(status, 200)
        self.assertEqual(payload["results"][0]["record"]["name"], "张三")

    def test_method_not_allowed(self):
        for path in ("/v1/encryption/encrypt", "/v1/encryption/decrypt", "/v1/encryption/rotate"):
            for method in ("GET", "PUT", "DELETE", "PATCH"):
                with self.subTest(method=method, path=path):
                    status, payload, allow = self.request(method, path)
                    self.assertEqual(status, 405)
                    self.assertEqual(payload["error"]["code"], "method_not_allowed")
                    self.assertEqual(allow, "POST")

    def test_unknown_path_404(self):
        status, payload, _ = self.request("POST", "/v1/encryption", body="{}", content_type="application/json")
        self.assertEqual(status, 404)
        self.assertEqual(payload["error"]["code"], "not_found")

    def test_unsupported_media_type(self):
        status, payload, _ = self.post("/v1/encryption/encrypt", base_payload(), content_type="text/plain")
        self.assertEqual(status, 415)
        self.assertEqual(payload["error"]["code"], "unsupported_media_type")

    def test_invalid_json(self):
        status, payload, _ = self.post("/v1/encryption/encrypt", "{not json")
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"]["code"], "invalid_json")

    def test_error_codes(self):
        encrypted = encrypt(base_payload())[0]["record"]
        cases = [
            ("/v1/encryption/encrypt", base_payload(records=[]), "invalid_request"),
            ("/v1/encryption/encrypt", base_payload(fields=[]), "invalid_fields"),
            ("/v1/encryption/encrypt", base_payload(fields=["/missing"]), "invalid_fields"),
            ("/v1/encryption/encrypt", base_payload(fields=["/name", "/name"]), "invalid_fields"),
            ("/v1/encryption/encrypt", base_payload(fields=["/contact", "/contact/phone"]), "invalid_fields"),
            ("/v1/encryption/encrypt", base_payload(key_id=""), "invalid_key"),
            ("/v1/encryption/encrypt", base_payload(secret=SECRET_31), "invalid_key"),
            ("/v1/encryption/encrypt", base_payload(secret=SECRET_33), "invalid_key"),
            ("/v1/encryption/encrypt", base_payload(context=""), "invalid_context"),
            ("/v1/encryption/decrypt", decrypt_payload([{"name": "x"}], ["/name"]), "invalid_envelope"),
            ("/v1/encryption/decrypt", decrypt_payload([encrypted], ["/name"], keys={"k-1": SECRET_32_B}), "invalid_ciphertext"),
            ("/v1/encryption/decrypt", decrypt_payload([encrypted], ["/name"], keys={"other": SECRET_32}), "invalid_key"),
            (
                "/v1/encryption/rotate",
                {
                    "records": [encrypted],
                    "fields": ["/name"],
                    "keys": {"k-1": SECRET_32},
                    "new_key_id": "k-2",
                    "new_secret": SECRET_31,
                },
                "invalid_key",
            ),
        ]
        for path, body, code in cases:
            with self.subTest(path=path, code=code):
                status, payload, _ = self.post(path, body)
                self.assertEqual(status, 422)
                self.assertEqual(payload["error"]["code"], code)

    def test_error_body_value_free(self):
        status, payload, _ = self.post("/v1/encryption/encrypt", base_payload(secret="bad-secret"))
        self.assertEqual(status, 422)
        self.assertNotIn("bad-secret", json.dumps(payload))

    def test_healthz_unchanged(self):
        status, payload, _ = self.request("GET", "/healthz")
        self.assertEqual(status, 200)
        self.assertEqual(payload["status"], "ok")


if __name__ == "__main__":
    unittest.main()
