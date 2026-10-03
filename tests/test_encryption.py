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
    _aes_gcm_seal,
    _encrypt_block,
    _expand_key,
)
from privacare.pseudonymizer import InvalidContext, InvalidFields, InvalidKey
from privacare.server import Handler
from privacare.service import Service

SECRET_32 = "A" * 43  # base64url of 32 zero bytes
SECRET_32_B = "B" * 43
SECRET_31 = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHg"  # decodes to 31 bytes
SECRET_33 = "A" * 44  # decodes to 33 bytes


def encrypt(payload):
    return Service().encrypt(payload)


def decrypt(payload):
    return Service().decrypt(payload)


def rotate(payload):
    return Service().rotate(payload)


def encrypt_payload(**overrides):
    payload = {
        "records": [
            {"name": "张三", "contact": {"phone": "13800138000"}, "ids": ["a/b", "m~n"]},
            {"name": "李四", "contact": {"phone": "13900139000"}, "ids": ["x", "y"]},
        ],
        "fields": ["/name", "/contact/phone", "/ids/0", "/ids/1"],
        "key_id": "k-1",
        "secret": SECRET_32,
    }
    payload.update(overrides)
    return payload


_DEFAULT = object()


def decrypt_payload(records, keys=_DEFAULT, fields=None):
    return {
        "records": records,
        "fields": fields if fields is not None else ["/name", "/contact/phone", "/ids/0", "/ids/1"],
        "keys": {"k-1": SECRET_32} if keys is _DEFAULT else keys,
    }


def encrypted_records(**overrides):
    """Records produced by a real encrypt call, ready to feed decrypt/rotate."""
    return [r["record"] for r in encrypt(encrypt_payload(**overrides))]


class AesGcmVectorTest(unittest.TestCase):
    def test_aes256_block_vector(self):
        key = bytes.fromhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
        block = bytes.fromhex("00112233445566778899aabbccddeeff")
        self.assertEqual(
            _encrypt_block(_expand_key(key), block).hex(),
            "8ea2b7ca516745bfeafc49904b496089",
        )

    def test_gcm_zero_vector(self):
        sealed = _aes_gcm_seal(b"\x00" * 32, b"\x00" * 12, b"\x00" * 16, b"")
        self.assertEqual(sealed[:16].hex(), "cea7403d4d606b6e074ec5d3baf39d18")
        self.assertEqual(sealed[16:].hex(), "d0d1c8a799996bf0265b98b5d48ab919")

    def test_gcm_vector_with_aad(self):
        key = bytes.fromhex("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308")
        nonce = bytes.fromhex("cafebabefacedbaddecaf888")
        plaintext = bytes.fromhex(
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
            "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39"
        )
        aad = bytes.fromhex("feedfacedeadbeeffeedfacedeadbeefabaddad2")
        sealed = _aes_gcm_seal(key, nonce, plaintext, aad)
        self.assertEqual(
            sealed[: len(plaintext)].hex(),
            "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa"
            "8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662",
        )
        self.assertEqual(sealed[len(plaintext) :].hex(), "76fc6ece0f4e1768cddf8853bb2d551b")


class EncryptTest(unittest.TestCase):
    def test_envelope_shape(self):
        [result] = encrypt(encrypt_payload(records=[{"name": "张三"}], fields=["/name"]))
        envelope = result["record"]["name"]
        self.assertEqual(set(envelope), {"alg", "key_id", "context", "nonce", "ciphertext"})
        self.assertEqual(envelope["alg"], ALG)
        self.assertEqual(envelope["key_id"], "k-1")
        self.assertEqual(envelope["context"], DEFAULT_CONTEXT)
        self.assertEqual(len(envelope["nonce"]), 16)  # 12 bytes, unpadded base64url
        for value in (envelope["nonce"], envelope["ciphertext"]):
            self.assertNotIn("=", value)
            self.assertNotIn("+", value)
            self.assertNotIn("/", value)

    def test_nonce_is_random_per_call(self):
        first = encrypt(encrypt_payload(records=[{"name": "张三"}], fields=["/name"]))
        second = encrypt(encrypt_payload(records=[{"name": "张三"}], fields=["/name"]))
        self.assertNotEqual(first[0]["record"]["name"], second[0]["record"]["name"])
        self.assertNotEqual(
            first[0]["record"]["name"]["nonce"], second[0]["record"]["name"]["nonce"]
        )

    def test_non_target_content_untouched_and_order_kept(self):
        results = encrypt(encrypt_payload())
        self.assertEqual([r["index"] for r in results], [0, 1])
        self.assertEqual(set(results[0]["record"]), {"name", "contact", "ids"})
        self.assertEqual(set(results[0]["record"]["contact"]), {"phone"})
        self.assertEqual(len(results[0]["record"]["ids"]), 2)

    def test_transformations_sorted_with_only_path_and_key_id(self):
        [result] = encrypt(encrypt_payload(records=[{"name": "a", "contact": {"phone": "p"}, "ids": ["x", "y"]}]))
        paths = [t["path"] for t in result["transformations"]]
        self.assertEqual(paths, ["/contact/phone", "/ids/0", "/ids/1", "/name"])
        for item in result["transformations"]:
            self.assertEqual(set(item), {"path", "key_id"})
            self.assertEqual(item["key_id"], "k-1")

    def test_context_default_and_explicit_equivalence(self):
        payload = encrypt_payload(records=[{"name": "a"}], fields=["/name"])
        omitted = encrypt(payload)[0]["record"]["name"]["context"]
        self.assertEqual(omitted, DEFAULT_CONTEXT)
        explicit = encrypt(encrypt_payload(
            records=[{"name": "a"}], fields=["/name"], context="ctx"
        ))[0]["record"]["name"]["context"]
        self.assertEqual(explicit, "ctx")
        null_ctx = encrypt(encrypt_payload(
            records=[{"name": "a"}], fields=["/name"], context=None
        ))[0]["record"]["name"]["context"]
        self.assertEqual(null_ctx, DEFAULT_CONTEXT)

    def test_caller_data_not_mutated(self):
        payload = encrypt_payload()
        snapshot = copy.deepcopy(payload)
        encrypt(payload)
        self.assertEqual(payload, snapshot)

    def test_response_does_not_echo_secret_or_plaintext(self):
        blob = json.dumps(encrypt(encrypt_payload()), ensure_ascii=False)
        self.assertNotIn(SECRET_32, blob)
        self.assertNotIn("张三", blob)
        self.assertNotIn("13800138000", blob)


class RoundTripTest(unittest.TestCase):
    def test_decrypt_restores_original_values_of_any_json_type(self):
        records = [
            {
                "s": "张三",
                "n": 42,
                "f": 0.5,
                "b": True,
                "z": None,
                "o": {"b": 1, "a": [1, "x", None]},
                "l": [1, 2, 3],
            }
        ]
        fields = ["/s", "/n", "/f", "/b", "/z", "/o", "/l"]
        encrypted = encrypt(encrypt_payload(records=records, fields=fields))
        restored = decrypt(decrypt_payload([encrypted[0]["record"]], fields=fields))
        self.assertEqual(restored[0]["record"], records[0])
        self.assertEqual(restored[0]["index"], 0)

    def test_decrypt_transformations_only_path_and_key_id(self):
        records = encrypted_records()
        results = decrypt(decrypt_payload(records))
        self.assertEqual([r["index"] for r in results], [0, 1])
        for result in results:
            paths = [t["path"] for t in result["transformations"]]
            self.assertEqual(paths, sorted(paths))
            for item in result["transformations"]:
                self.assertEqual(set(item), {"path", "key_id"})
                self.assertEqual(item["key_id"], "k-1")

    def test_decrypt_with_multiple_key_versions(self):
        first = encrypt(encrypt_payload(records=[{"name": "a"}], fields=["/name"], key_id="k-1"))[0]["record"]
        second = encrypt(encrypt_payload(
            records=[{"name": "b"}], fields=["/name"], key_id="k-2", secret=SECRET_32_B
        ))[0]["record"]
        results = decrypt(
            decrypt_payload([first, second], keys={"k-1": SECRET_32, "k-2": SECRET_32_B}, fields=["/name"])
        )
        self.assertEqual(results[0]["record"], {"name": "a"})
        self.assertEqual(results[1]["record"], {"name": "b"})
        self.assertEqual(results[0]["transformations"], [{"path": "/name", "key_id": "k-1"}])
        self.assertEqual(results[1]["transformations"], [{"path": "/name", "key_id": "k-2"}])

    def test_moved_envelope_fails_authentication(self):
        [result] = encrypt(encrypt_payload(records=[{"a": "x", "b": "y"}], fields=["/a", "/b"]))
        record = result["record"]
        record["a"], record["b"] = record["b"], record["a"]
        with self.assertRaises(InvalidCiphertext):
            decrypt(decrypt_payload([record], fields=["/a", "/b"]))

    def test_tampered_ciphertext_fails(self):
        records = encrypted_records()
        envelope = dict(records[0]["name"])
        raw = envelope["ciphertext"]
        envelope["ciphertext"] = ("A" if raw[0] != "A" else "B") + raw[1:]
        records[0]["name"] = envelope
        with self.assertRaises(InvalidCiphertext):
            decrypt(decrypt_payload(records))

    def test_wrong_secret_fails_authentication(self):
        records = encrypted_records()
        with self.assertRaises(InvalidCiphertext):
            decrypt(decrypt_payload(records, keys={"k-1": SECRET_32_B}))

    def test_unknown_key_id_is_invalid_key(self):
        records = encrypted_records()
        with self.assertRaises(InvalidKey):
            decrypt(decrypt_payload(records, keys={"k-other": SECRET_32}))

    def test_decrypt_does_not_mutate_input(self):
        payload = decrypt_payload(encrypted_records())
        snapshot = copy.deepcopy(payload)
        decrypt(payload)
        self.assertEqual(payload, snapshot)


class RotateTest(unittest.TestCase):
    def rotate_payload(self, records, keys=None, **overrides):
        payload = {
            "records": records,
            "fields": ["/name", "/contact/phone", "/ids/0", "/ids/1"],
            "keys": keys if keys is not None else {"k-1": SECRET_32},
            "new_key_id": "k-2",
            "new_secret": SECRET_32_B,
        }
        payload.update(overrides)
        return payload

    def test_rotate_then_decrypt_with_new_key(self):
        original = encrypt_payload()["records"]
        rotated = rotate(self.rotate_payload(encrypted_records()))
        self.assertEqual([r["index"] for r in rotated], [0, 1])
        for result in rotated:
            for item in result["transformations"]:
                self.assertEqual(set(item), {"path", "old_key_id", "new_key_id"})
                self.assertEqual(item["old_key_id"], "k-1")
                self.assertEqual(item["new_key_id"], "k-2")
            paths = [t["path"] for t in result["transformations"]]
            self.assertEqual(paths, sorted(paths))
        restored = decrypt(
            decrypt_payload(
                [r["record"] for r in rotated],
                keys={"k-2": SECRET_32_B},
            )
        )
        self.assertEqual([r["record"] for r in restored], original)

    def test_rotated_envelope_keeps_context_and_new_shape(self):
        records = encrypted_records(records=[{"name": "a"}], fields=["/name"], context="ctx")
        [result] = rotate(self.rotate_payload(records, fields=["/name"]))
        envelope = result["record"]["name"]
        self.assertEqual(set(envelope), {"alg", "key_id", "context", "nonce", "ciphertext"})
        self.assertEqual(envelope["key_id"], "k-2")
        self.assertEqual(envelope["context"], "ctx")

    def test_rotate_mixed_key_versions(self):
        first = encrypt(encrypt_payload(records=[{"name": "a"}], fields=["/name"], key_id="k-1"))[0]["record"]
        second = encrypt(encrypt_payload(
            records=[{"name": "b"}], fields=["/name"], key_id="k-2", secret=SECRET_32_B
        ))[0]["record"]
        results = rotate(
            self.rotate_payload(
                [first, second],
                keys={"k-1": SECRET_32, "k-2": SECRET_32_B},
                fields=["/name"],
                new_key_id="k-3",
                new_secret="C" * 43,
            )
        )
        self.assertEqual(results[0]["transformations"][0]["old_key_id"], "k-1")
        self.assertEqual(results[1]["transformations"][0]["old_key_id"], "k-2")
        restored = decrypt(
            decrypt_payload([r["record"] for r in results], keys={"k-3": "C" * 43}, fields=["/name"])
        )
        self.assertEqual([r["record"] for r in restored], [{"name": "a"}, {"name": "b"}])

    def test_rotate_is_all_or_nothing(self):
        good, bad = encrypted_records()
        bad["name"] = {"not": "an envelope"}
        with self.assertRaises(InvalidEnvelope):
            rotate(self.rotate_payload([good, bad]))

    def test_rotate_does_not_mutate_input(self):
        payload = self.rotate_payload(encrypted_records())
        snapshot = copy.deepcopy(payload)
        rotate(payload)
        self.assertEqual(payload, snapshot)

    def test_rotate_response_does_not_echo_secrets(self):
        blob = json.dumps(rotate(self.rotate_payload(encrypted_records())), ensure_ascii=False)
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
        for fields in (None, "x", 1, [], [""], ["name"], ["/name", 1], ["/name", "/name"]):
            with self.subTest(fields=fields):
                with self.assertRaises(InvalidFields):
                    encrypt(encrypt_payload(fields=fields))

    def test_root_pointer_rejected(self):
        with self.assertRaises(InvalidFields):
            encrypt(encrypt_payload(fields=[""]))

    def test_bad_pointer_syntax(self):
        for pointer in ("/a~2", "/a~", "/a~x"):
            with self.subTest(pointer=pointer):
                with self.assertRaises(InvalidFields):
                    encrypt(encrypt_payload(fields=[pointer]))

    def test_overlapping_paths_rejected(self):
        for fields in (
            ["/a", "/a/b"],
            ["/a/b", "/a"],
            ["/a", "/a"],
            ["/ids/0", "/ids"],
            ["/contact", "/contact/phone"],
        ):
            with self.subTest(fields=fields):
                with self.assertRaises(InvalidFields):
                    encrypt(encrypt_payload(fields=fields))

    def test_path_missing_or_out_of_bounds(self):
        for pointer in ("/missing", "/contact/fax", "/ids/2", "/ids/-", "/ids/01", "/name/x"):
            with self.subTest(pointer=pointer):
                with self.assertRaises(InvalidFields):
                    encrypt(encrypt_payload(fields=[pointer]))

    def test_every_record_must_resolve(self):
        payload = encrypt_payload(records=[{"name": "ok"}, {"other": "x"}], fields=["/name"])
        try:
            encrypt(payload)
        except InvalidFields as exc:
            self.assertNotIn("ok", str(exc))
        else:
            self.fail("expected InvalidFields")


class InvalidKeyTest(unittest.TestCase):
    def test_bad_key_id(self):
        for key_id in (None, "", 1, [], {}):
            with self.subTest(key_id=key_id):
                with self.assertRaises(InvalidKey):
                    encrypt(encrypt_payload(key_id=key_id))

    def test_bad_secret(self):
        for secret in (
            None,
            "",
            1,
            "AAAA",
            SECRET_31,  # 31 bytes
            SECRET_33,  # 33 bytes: must be exactly 32
            "A" * 42 + "=",  # padding is not allowed
            "A" * 42 + "+",
            "A" * 42 + " ",
            "A" * 45,  # length mod 4 == 1 is impossible in base64
        ):
            with self.subTest(secret=secret):
                with self.assertRaises(InvalidKey):
                    encrypt(encrypt_payload(secret=secret))

    def test_bad_keys(self):
        records = encrypted_records()
        for keys in (None, [], "x", 1, {}, {"": SECRET_32}, {"k-1": "short"}, {"k-1": SECRET_33}):
            with self.subTest(keys=keys):
                with self.assertRaises(InvalidKey):
                    decrypt(decrypt_payload(records, keys=keys))

    def test_bad_new_key(self):
        records = encrypted_records()
        base = {
            "records": records,
            "fields": ["/name"],
            "keys": {"k-1": SECRET_32},
            "new_key_id": "k-2",
            "new_secret": SECRET_32_B,
        }
        for overrides in (
            {"new_key_id": ""},
            {"new_key_id": None},
            {"new_key_id": 1},
            {"new_secret": None},
            {"new_secret": SECRET_31},
            {"new_secret": SECRET_33},
        ):
            with self.subTest(overrides=overrides):
                with self.assertRaises(InvalidKey):
                    rotate({**base, **overrides})

    def test_key_errors_do_not_echo_secret(self):
        try:
            encrypt(encrypt_payload(secret=SECRET_31))
        except InvalidKey as exc:
            self.assertNotIn(SECRET_31, str(exc))
        else:
            self.fail("expected InvalidKey")


class InvalidContextTest(unittest.TestCase):
    def test_bad_context(self):
        for context in ("", 1, True, [], {}):
            with self.subTest(context=context):
                with self.assertRaises(InvalidContext):
                    encrypt(encrypt_payload(context=context))


class InvalidEnvelopeTest(unittest.TestCase):
    def decrypt_one(self, envelope):
        return decrypt(decrypt_payload([{"name": envelope}], fields=["/name"]))

    def good_envelope(self):
        return encrypted_records(records=[{"name": "a"}], fields=["/name"])[0]["name"]

    def test_non_envelope_values(self):
        for value in ("x", 1, None, True, [], {}, {"alg": ALG}):
            with self.subTest(value=value):
                with self.assertRaises(InvalidEnvelope):
                    self.decrypt_one(value)

    def test_missing_and_extra_members(self):
        envelope = self.good_envelope()
        del envelope["nonce"]
        with self.assertRaises(InvalidEnvelope):
            self.decrypt_one(envelope)
        envelope = self.good_envelope()
        envelope["extra"] = "x"
        with self.assertRaises(InvalidEnvelope):
            self.decrypt_one(envelope)

    def test_bad_member_values(self):
        for key, value in (
            ("alg", "A128GCM"),
            ("alg", ""),
            ("key_id", ""),
            ("key_id", 1),
            ("context", ""),
            ("context", None),
            ("nonce", "!!!"),
            ("nonce", "AA"),  # decodes to 1 byte, not 12
            ("ciphertext", "!!!"),
            ("ciphertext", "AA"),  # shorter than the 16-byte tag
        ):
            with self.subTest(key=key, value=value):
                envelope = self.good_envelope()
                envelope[key] = value
                with self.assertRaises(InvalidEnvelope):
                    self.decrypt_one(envelope)


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

    def test_encrypt_decrypt_rotate_round_trip_over_http(self):
        status, payload, _ = self.post("/v1/encryption/encrypt", encrypt_payload())
        self.assertEqual(status, 200)
        results = payload["results"]
        self.assertEqual([r["index"] for r in results], [0, 1])
        blob = json.dumps(payload, ensure_ascii=False)
        self.assertNotIn("张三", blob)
        self.assertNotIn(SECRET_32, blob)

        records = [r["record"] for r in results]
        status, payload, _ = self.post("/v1/encryption/decrypt", decrypt_payload(records))
        self.assertEqual(status, 200)
        self.assertEqual(
            [r["record"] for r in payload["results"]], encrypt_payload()["records"]
        )

        status, payload, _ = self.post(
            "/v1/encryption/rotate",
            {
                "records": records,
                "fields": ["/name", "/contact/phone", "/ids/0", "/ids/1"],
                "keys": {"k-1": SECRET_32},
                "new_key_id": "k-2",
                "new_secret": SECRET_32_B,
            },
        )
        self.assertEqual(status, 200)
        rotated = [r["record"] for r in payload["results"]]
        status, payload, _ = self.post(
            "/v1/encryption/decrypt",
            decrypt_payload(rotated, keys={"k-2": SECRET_32_B}),
        )
        self.assertEqual(status, 200)
        self.assertEqual(
            [r["record"] for r in payload["results"]], encrypt_payload()["records"]
        )

    def test_method_not_allowed(self):
        for path in ("/v1/encryption/encrypt", "/v1/encryption/decrypt", "/v1/encryption/rotate"):
            for method in ("GET", "PUT", "DELETE", "PATCH"):
                with self.subTest(path=path, method=method):
                    status, payload, allow = self.request(method, path)
                    self.assertEqual(status, 405)
                    self.assertEqual(payload["error"]["code"], "method_not_allowed")
                    self.assertEqual(allow, "POST")

    def test_unknown_path_404(self):
        status, payload, _ = self.request(
            "POST", "/v1/encryption/nope", body="{}", content_type="application/json"
        )
        self.assertEqual(status, 404)
        self.assertEqual(payload["error"]["code"], "not_found")

    def test_unsupported_media_type(self):
        status, payload, _ = self.post(
            "/v1/encryption/encrypt", encrypt_payload(), content_type="text/plain"
        )
        self.assertEqual(status, 415)
        self.assertEqual(payload["error"]["code"], "unsupported_media_type")

    def test_invalid_json(self):
        status, payload, _ = self.post("/v1/encryption/encrypt", "{not json")
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"]["code"], "invalid_json")

    def test_error_codes(self):
        records = encrypted_records()
        tampered = copy.deepcopy(records)
        raw = tampered[0]["name"]["ciphertext"]
        tampered[0]["name"]["ciphertext"] = ("A" if raw[0] != "A" else "B") + raw[1:]
        cases = [
            ("/v1/encryption/encrypt", encrypt_payload(records=[]), "invalid_request"),
            ("/v1/encryption/encrypt", encrypt_payload(fields=[]), "invalid_fields"),
            ("/v1/encryption/encrypt", encrypt_payload(fields=["/missing"]), "invalid_fields"),
            ("/v1/encryption/encrypt", encrypt_payload(fields=["/a", "/a/b"]), "invalid_fields"),
            ("/v1/encryption/encrypt", encrypt_payload(key_id=""), "invalid_key"),
            ("/v1/encryption/encrypt", encrypt_payload(secret=SECRET_31), "invalid_key"),
            ("/v1/encryption/encrypt", encrypt_payload(context=""), "invalid_context"),
            ("/v1/encryption/decrypt", decrypt_payload(records, keys={}), "invalid_key"),
            ("/v1/encryption/decrypt", decrypt_payload([{"name": "x"}], fields=["/name"]), "invalid_envelope"),
            ("/v1/encryption/decrypt", decrypt_payload(tampered), "invalid_ciphertext"),
            (
                "/v1/encryption/rotate",
                {
                    "records": records,
                    "fields": ["/name"],
                    "keys": {"k-1": SECRET_32},
                    "new_key_id": "k-2",
                    "new_secret": "bad",
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
        status, payload, _ = self.post("/v1/encryption/encrypt", encrypt_payload(secret="bad-secret"))
        self.assertEqual(status, 422)
        self.assertNotIn("bad-secret", json.dumps(payload))


if __name__ == "__main__":
    unittest.main()
