"""Authenticated field-level encryption, decryption and key rotation.

Pure and request-scoped like the other modules: records, keys and
envelopes are read from the current payload only, nothing is persisted
between requests, the caller's data is never mutated, and failures never
return partial output. Target values are canonicalized under RFC 8785
(JSON Canonicalization Scheme) and encrypted with AES-256-GCM; the
authentication data binds the key version, the context and the leaf's
canonical JSON Pointer, so an envelope cannot be replayed at a different
path or under a different context. The envelope carries only ``alg``,
``key_id``, ``context``, ``nonce`` and ``ciphertext`` — never plaintext.
"""

from __future__ import annotations

import base64
import binascii
import copy
import hmac
import json
import os
import re
import struct
from typing import Any

from .audit import InvalidAuditEvent, _canonicalize
from .classifier import InvalidRequest, _pointer, _validate_records
from .pseudonymizer import InvalidContext, InvalidFields, InvalidKey

#: Context used when the caller does not supply one.
DEFAULT_CONTEXT = "privacare.encryption.v1"

#: JOSE algorithm identifier carried by every envelope.
ALG = "A256GCM"

_NONCE_LEN = 12
_TAG_LEN = 16
_KEY_LEN = 32

_BASE64URL_RE = re.compile(r"^[A-Za-z0-9_-]+$")

_ENVELOPE_KEYS = frozenset({"alg", "key_id", "context", "nonce", "ciphertext"})


class InvalidEnvelope(ValueError):
    """An envelope's structure or encoding is malformed."""


class InvalidCiphertext(ValueError):
    """Ciphertext authentication failed: moved, tampered or wrong key."""


# --- AES-256 (FIPS-197) ------------------------------------------------------

_SBOX = (
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
)

_RCON = (0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D)


def _gf_mul8(a: int, b: int) -> int:
    """Multiply two bytes in GF(2^8) modulo the AES polynomial."""
    product = 0
    for _ in range(8):
        if b & 1:
            product ^= a
        carry = a & 0x80
        a = (a << 1) & 0xFF
        if carry:
            a ^= 0x1B
        b >>= 1
    return product


def _expand_key(key: bytes) -> list[list[int]]:
    """AES-256 key schedule: 15 round keys of 16 bytes each."""
    nk, nr = 8, 14
    words = [list(key[4 * i:4 * i + 4]) for i in range(nk)]
    for i in range(nk, 4 * (nr + 1)):
        temp = list(words[i - 1])
        if i % nk == 0:
            temp = [_SBOX[b] for b in temp[1:] + temp[:1]]
            temp[0] ^= _RCON[i // nk - 1]
        elif i % nk == 4:
            temp = [_SBOX[b] for b in temp]
        words.append([words[i - nk][j] ^ temp[j] for j in range(4)])
    return [
        [b for word in words[4 * r:4 * r + 4] for b in word]
        for r in range(nr + 1)
    ]


def _shift_rows(state: list[int]) -> None:
    # state[4*c + r] is row r, column c; row r rotates left by r.
    for r in (1, 2, 3):
        row = [state[4 * c + r] for c in range(4)]
        for c in range(4):
            state[4 * c + r] = row[(c + r) % 4]


def _aes_encrypt_block(round_keys: list[list[int]], block: bytes) -> bytes:
    state = list(block)
    for i in range(16):
        state[i] ^= round_keys[0][i]
    for rnd in range(1, 14):
        for i in range(16):
            state[i] = _SBOX[state[i]]
        _shift_rows(state)
        for c in range(4):
            i = 4 * c
            a0, a1, a2, a3 = state[i:i + 4]
            state[i] = _gf_mul8(a0, 2) ^ _gf_mul8(a1, 3) ^ a2 ^ a3
            state[i + 1] = a0 ^ _gf_mul8(a1, 2) ^ _gf_mul8(a2, 3) ^ a3
            state[i + 2] = a0 ^ a1 ^ _gf_mul8(a2, 2) ^ _gf_mul8(a3, 3)
            state[i + 3] = _gf_mul8(a0, 3) ^ a1 ^ a2 ^ _gf_mul8(a3, 2)
        for i in range(16):
            state[i] ^= round_keys[rnd][i]
    for i in range(16):
        state[i] = _SBOX[state[i]]
    _shift_rows(state)
    for i in range(16):
        state[i] ^= round_keys[14][i]
    return bytes(state)


# --- GCM (NIST SP 800-38D) ---------------------------------------------------

_GHASH_R = 0xE1000000000000000000000000000000


def _gcm_mul(x: int, y: int) -> int:
    """Multiply two 128-bit blocks in GF(2^128) as GCM defines it."""
    z = 0
    v = y
    for i in range(128):
        if (x >> (127 - i)) & 1:
            z ^= v
        v = (v >> 1) ^ _GHASH_R if v & 1 else v >> 1
    return z


def _ghash(h: int, data: bytes) -> int:
    y = 0
    for off in range(0, len(data), 16):
        y = _gcm_mul(y ^ int.from_bytes(data[off:off + 16], "big"), h)
    return y


def _pad16(data: bytes) -> bytes:
    return data + b"\x00" * (-len(data) % 16)


def _gcm_keystream_xor(round_keys: list[list[int]], j0: bytes, data: bytes) -> bytes:
    out = bytearray()
    counter = int.from_bytes(j0, "big")
    for off in range(0, len(data), 16):
        counter = (counter & ~0xFFFFFFFF) | ((counter + 1) & 0xFFFFFFFF)
        mask = _aes_encrypt_block(round_keys, counter.to_bytes(16, "big"))
        chunk = data[off:off + 16]
        out.extend(a ^ b for a, b in zip(chunk, mask))
    return bytes(out)


def _gcm_tag(round_keys: list[list[int]], j0: bytes, aad: bytes, ciphertext: bytes) -> bytes:
    h = int.from_bytes(_aes_encrypt_block(round_keys, b"\x00" * 16), "big")
    lengths = (len(aad) * 8).to_bytes(8, "big") + (len(ciphertext) * 8).to_bytes(8, "big")
    s = _ghash(h, _pad16(aad) + _pad16(ciphertext) + lengths)
    mask = int.from_bytes(_aes_encrypt_block(round_keys, j0), "big")
    return (mask ^ s).to_bytes(16, "big")


def _aes_gcm_encrypt(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes) -> bytes:
    """Encrypt and return ciphertext with the 16-byte tag appended."""
    round_keys = _expand_key(key)
    j0 = nonce + b"\x00\x00\x00\x01"
    ciphertext = _gcm_keystream_xor(round_keys, j0, plaintext)
    return ciphertext + _gcm_tag(round_keys, j0, aad, ciphertext)


def _aes_gcm_decrypt(key: bytes, nonce: bytes, sealed: bytes, aad: bytes) -> bytes:
    """Verify the tag and decrypt; raises InvalidCiphertext on mismatch."""
    ciphertext, tag = sealed[:-_TAG_LEN], sealed[-_TAG_LEN:]
    round_keys = _expand_key(key)
    j0 = nonce + b"\x00\x00\x00\x01"
    expected = _gcm_tag(round_keys, j0, aad, ciphertext)
    if not hmac.compare_digest(tag, expected):
        raise InvalidCiphertext("ciphertext authentication failed")
    return _gcm_keystream_xor(round_keys, j0, ciphertext)


# --- base64url and small validators ------------------------------------------


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64url_decode(raw: Any, error: type[ValueError], what: str) -> bytes:
    if not isinstance(raw, str) or not _BASE64URL_RE.fullmatch(raw):
        raise error(f"{what} must be an unpadded base64url string")
    if len(raw) % 4 == 1:
        raise error(f"{what} must be an unpadded base64url string")
    padded = raw + "=" * (-len(raw) % 4)
    try:
        return base64.urlsafe_b64decode(padded.encode("ascii"))
    except (binascii.Error, ValueError):
        raise error(f"{what} must be an unpadded base64url string") from None


def _decode_secret(raw: Any) -> bytes:
    """Validate an unpadded base64url string decoding to exactly 32 bytes."""
    key = _b64url_decode(raw, InvalidKey, "secret")
    if len(key) != _KEY_LEN:
        raise InvalidKey("secret must decode to exactly 32 bytes")
    return key


def _validate_key_id(raw: Any) -> str:
    if not isinstance(raw, str) or not raw:
        raise InvalidKey("key_id must be a non-empty string")
    return raw


def _validate_context(raw: Any) -> str:
    # Absent (including a literal null) means "use the fixed default"; a
    # present value must be a non-empty string.
    if raw is None:
        return DEFAULT_CONTEXT
    if not isinstance(raw, str) or not raw:
        raise InvalidContext("context must be a non-empty string")
    return raw


def _validate_keys(raw: Any) -> dict[str, bytes]:
    if not isinstance(raw, dict) or not raw:
        raise InvalidKey("keys must be a non-empty object mapping key ids to secrets")
    keys: dict[str, bytes] = {}
    for key_id, secret in raw.items():
        if not isinstance(key_id, str) or not key_id:
            raise InvalidKey("keys must map non-empty key id strings to secrets")
        keys[key_id] = _decode_secret(secret)
    return keys


# --- field pointers ------------------------------------------------------------


def _parse_pointer(raw: Any) -> tuple[str, ...]:
    """Parse a non-root RFC 6901 JSON Pointer into segments."""
    if not isinstance(raw, str) or not raw.startswith("/"):
        raise InvalidFields("each field must be a non-root JSON Pointer string starting with '/'")
    segments: list[str] = []
    for part in raw.split("/")[1:]:
        out: list[str] = []
        i = 0
        while i < len(part):
            ch = part[i]
            if ch == "~":
                nxt = part[i + 1] if i + 1 < len(part) else ""
                if nxt == "0":
                    out.append("~")
                elif nxt == "1":
                    out.append("/")
                else:
                    raise InvalidFields("invalid '~' escape in JSON pointer")
                i += 2
            else:
                out.append(ch)
                i += 1
        segments.append("".join(out))
    return tuple(segments)


def _validate_fields(raw: Any) -> list[tuple[str, ...]]:
    if not isinstance(raw, list) or not raw:
        raise InvalidFields("fields must be a non-empty array of JSON Pointer strings")
    pointers: list[tuple[str, ...]] = []
    seen: set[tuple[str, ...]] = set()
    for item in raw:
        segments = _parse_pointer(item)
        if segments in seen:
            raise InvalidFields("fields must not contain duplicates")
        seen.add(segments)
        for other in pointers:
            shared = min(len(segments), len(other))
            if segments[:shared] == other[:shared]:
                raise InvalidFields("field pointers must not be ancestors or descendants of each other")
        pointers.append(segments)
    return pointers


def _resolve(record: dict, segments: tuple[str, ...]) -> Any:
    """Resolve a JSON Pointer on a record; any JSON value may be targeted."""
    node: Any = record
    for segment in segments:
        if isinstance(node, dict):
            if segment not in node:
                raise InvalidFields("every field pointer must resolve on every record")
            node = node[segment]
        elif isinstance(node, list):
            # RFC 6901: "-" never resolves, only "0" may start with '0'.
            if segment == "-" or not segment.isdigit():
                raise InvalidFields("invalid array index in field pointer")
            if segment != "0" and segment[0] == "0":
                raise InvalidFields("array indices must not have leading zeros")
            index = int(segment)
            if index >= len(node):
                raise InvalidFields("every field pointer must resolve on every record")
            node = node[index]
        else:
            raise InvalidFields("every field pointer must resolve on every record")
    return node


def _set_leaf(node: Any, segments: tuple[str, ...], value: Any) -> None:
    for segment in segments[:-1]:
        node = node[int(segment)] if isinstance(node, list) else node[segment]
    last = segments[-1]
    if isinstance(node, list):
        node[int(last)] = value
    else:
        node[last] = value


# --- envelopes -----------------------------------------------------------------


def _aad(key_id: str, context: str, path: str) -> bytes:
    """Authenticated data binding key version, context and canonical path."""
    parts = (key_id, context, path)
    return b"ev1" + b"".join(
        struct.pack(">I", len(part.encode("utf-8"))) + part.encode("utf-8") for part in parts
    )


def _canonical_bytes(value: Any) -> bytes:
    try:
        return _canonicalize(value).encode("utf-8")
    except (InvalidAuditEvent, UnicodeEncodeError):
        raise InvalidFields("field values must be finite JSON values") from None


def _seal(key: bytes, key_id: str, context: str, path: str, value: Any) -> dict:
    plaintext = _canonical_bytes(value)
    nonce = os.urandom(_NONCE_LEN)
    sealed = _aes_gcm_encrypt(key, nonce, plaintext, _aad(key_id, context, path))
    return {
        "alg": ALG,
        "key_id": key_id,
        "context": context,
        "nonce": _b64url_encode(nonce),
        "ciphertext": _b64url_encode(sealed),
    }


def _validate_envelope(raw: Any) -> tuple[str, str, bytes, bytes]:
    """Check envelope shape and encodings; return its decoded parts."""
    if not isinstance(raw, dict) or set(raw) != _ENVELOPE_KEYS:
        raise InvalidEnvelope("envelope must be an object with exactly alg, key_id, context, nonce, ciphertext")
    if raw["alg"] != ALG:
        raise InvalidEnvelope("envelope alg must be A256GCM")
    key_id = raw["key_id"]
    if not isinstance(key_id, str) or not key_id:
        raise InvalidEnvelope("envelope key_id must be a non-empty string")
    context = raw["context"]
    if not isinstance(context, str) or not context:
        raise InvalidEnvelope("envelope context must be a non-empty string")
    nonce = _b64url_decode(raw["nonce"], InvalidEnvelope, "envelope nonce")
    if len(nonce) != _NONCE_LEN:
        raise InvalidEnvelope("envelope nonce must decode to 12 bytes")
    sealed = _b64url_decode(raw["ciphertext"], InvalidEnvelope, "envelope ciphertext")
    if len(sealed) < _TAG_LEN:
        raise InvalidEnvelope("envelope ciphertext must carry a 16-byte authentication tag")
    return key_id, context, nonce, sealed


def _open(envelope: Any, keys: dict[str, bytes], path: str) -> Any:
    """Validate, authenticate and decrypt one envelope; restore the value."""
    key_id, context, nonce, sealed = _validate_envelope(envelope)
    key = keys.get(key_id)
    if key is None:
        raise InvalidKey("no key available for the envelope's key_id")
    plaintext = _aes_gcm_decrypt(key, nonce, sealed, _aad(key_id, context, path))
    try:
        return json.loads(plaintext.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise InvalidCiphertext("ciphertext authentication failed") from None


# --- request handlers ----------------------------------------------------------


def encrypt_request(payload: Any) -> list[dict]:
    """Validate a /v1/encryption/encrypt payload and encrypt every record."""
    records = _validate_records(payload)
    pointers = _validate_fields(payload.get("fields"))
    # Every pointer must resolve on every record before anything is
    # transformed — failures never return partial output.
    for record in records:
        for segments in pointers:
            _resolve(record, segments)
    key_id = _validate_key_id(payload.get("key_id"))
    key = _decode_secret(payload.get("secret"))
    context = _validate_context(payload.get("context"))

    paths = [_pointer(segments) for segments in pointers]
    results: list[dict] = []
    for index, record in enumerate(records):
        transformed = copy.deepcopy(record)
        for segments, path in zip(pointers, paths):
            envelope = _seal(key, key_id, context, path, _resolve(record, segments))
            _set_leaf(transformed, segments, envelope)
        transformations = [{"path": path, "key_id": key_id} for path in sorted(paths)]
        results.append(
            {"index": index, "record": transformed, "transformations": transformations}
        )
    return results


def decrypt_request(payload: Any) -> list[dict]:
    """Validate a /v1/encryption/decrypt payload and restore every record."""
    records = _validate_records(payload)
    pointers = _validate_fields(payload.get("fields"))
    for record in records:
        for segments in pointers:
            _resolve(record, segments)
    keys = _validate_keys(payload.get("keys"))

    paths = [_pointer(segments) for segments in pointers]
    results: list[dict] = []
    for index, record in enumerate(records):
        transformed = copy.deepcopy(record)
        used: dict[str, str] = {}
        for segments, path in zip(pointers, paths):
            envelope = _resolve(record, segments)
            key_id, _, _, _ = _validate_envelope(envelope)
            _set_leaf(transformed, segments, _open(envelope, keys, path))
            used[path] = key_id
        transformations = [
            {"path": path, "key_id": used[path]} for path in sorted(paths)
        ]
        results.append(
            {"index": index, "record": transformed, "transformations": transformations}
        )
    return results


def rotate_request(payload: Any) -> list[dict]:
    """Validate a /v1/encryption/rotate payload and re-encrypt every record."""
    records = _validate_records(payload)
    pointers = _validate_fields(payload.get("fields"))
    for record in records:
        for segments in pointers:
            _resolve(record, segments)
    keys = _validate_keys(payload.get("keys"))
    new_key_id = _validate_key_id(payload.get("new_key_id"))
    new_key = _decode_secret(payload.get("new_secret"))

    paths = [_pointer(segments) for segments in pointers]
    results: list[dict] = []
    for index, record in enumerate(records):
        transformed = copy.deepcopy(record)
        rotated: dict[str, str] = {}
        for segments, path in zip(pointers, paths):
            envelope = _resolve(record, segments)
            old_key_id, context, _, _ = _validate_envelope(envelope)
            value = _open(envelope, keys, path)
            _set_leaf(transformed, segments, _seal(new_key, new_key_id, context, path, value))
            rotated[path] = old_key_id
        transformations = [
            {"path": path, "old_key_id": rotated[path], "new_key_id": new_key_id}
            for path in sorted(paths)
        ]
        results.append(
            {"index": index, "record": transformed, "transformations": transformations}
        )
    return results
