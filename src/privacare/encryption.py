"""Authenticated field-level encryption, decryption and key rotation.

Values at caller-selected JSON Pointers are canonicalized per RFC 8785
(JSON Canonicalization Scheme) and sealed with AES-256-GCM into a
self-describing envelope. The authentication data binds the key version,
the context and the leaf's canonical JSON Pointer, so an envelope moved
to a different path or key context fails to open. Everything is derived
from the current request only — the caller's data is never mutated, no
record, key or mapping is kept between requests, and every nonce is
generated fresh at random.
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

#: The only algorithm this module seals and opens.
ALG = "A256GCM"

_NONCE_LEN = 12
_TAG_LEN = 16
_ENVELOPE_KEYS = frozenset({"alg", "key_id", "context", "nonce", "ciphertext"})

_BASE64URL_RE = re.compile(r"^[A-Za-z0-9_-]+$")


class InvalidEnvelope(ValueError):
    """An envelope's structure or encoding is malformed."""


class InvalidCiphertext(ValueError):
    """An envelope failed authentication or was moved or tampered with."""


# --- AES-256 (FIPS-197) ------------------------------------------------------
# Pure-Python AES used only through GCM below; the state is kept as 16
# bytes in column-major order, matching the byte order of the block.


def _gf_mul(a: int, b: int) -> int:
    """Multiply two bytes in the AES field GF(2^8)."""
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


def _gf_pow(x: int, n: int) -> int:
    result = 1
    while n:
        if n & 1:
            result = _gf_mul(result, x)
        x = _gf_mul(x, x)
        n >>= 1
    return result


def _rotl8(x: int, n: int) -> int:
    return ((x << n) | (x >> (8 - n))) & 0xFF


def _build_sbox() -> tuple[int, ...]:
    sbox = []
    for x in range(256):
        inv = 0 if x == 0 else _gf_pow(x, 254)
        sbox.append(inv ^ _rotl8(inv, 1) ^ _rotl8(inv, 2) ^ _rotl8(inv, 3) ^ _rotl8(inv, 4) ^ 0x63)
    return tuple(sbox)


_SBOX = _build_sbox()


def _expand_key(key: bytes) -> list[bytes]:
    """Expand a 32-byte key into 15 round keys (Nk=8, Nr=14)."""
    words = [key[4 * i : 4 * i + 4] for i in range(8)]
    rcon = 1
    while len(words) < 60:
        temp = words[-1]
        i = len(words)
        if i % 8 == 0:
            temp = bytes((_SBOX[temp[1]] ^ rcon, _SBOX[temp[2]], _SBOX[temp[3]], _SBOX[temp[0]]))
            rcon = _gf_mul(rcon, 2)
        elif i % 8 == 4:
            temp = bytes(_SBOX[b] for b in temp)
        words.append(bytes(a ^ b for a, b in zip(words[i - 8], temp)))
    return [b"".join(words[4 * r : 4 * r + 4]) for r in range(15)]


def _shift_rows(state: list[int]) -> list[int]:
    out = [0] * 16
    for r in range(4):
        for c in range(4):
            out[r + 4 * c] = state[r + 4 * ((c + r) % 4)]
    return out


def _mix_columns(state: list[int]) -> list[int]:
    out = list(state)
    for c in range(4):
        i = 4 * c
        s0, s1, s2, s3 = state[i : i + 4]
        t = s0 ^ s1 ^ s2 ^ s3
        out[i] = s0 ^ t ^ _gf_mul(s0 ^ s1, 2)
        out[i + 1] = s1 ^ t ^ _gf_mul(s1 ^ s2, 2)
        out[i + 2] = s2 ^ t ^ _gf_mul(s2 ^ s3, 2)
        out[i + 3] = s3 ^ t ^ _gf_mul(s3 ^ s0, 2)
    return out


def _encrypt_block(round_keys: list[bytes], block: bytes) -> bytes:
    state = [b ^ k for b, k in zip(block, round_keys[0])]
    for rnd in range(1, 14):
        state = [_SBOX[b] for b in state]
        state = _shift_rows(state)
        state = _mix_columns(state)
        state = [b ^ k for b, k in zip(state, round_keys[rnd])]
    state = [_SBOX[b] for b in state]
    state = _shift_rows(state)
    return bytes(b ^ k for b, k in zip(state, round_keys[14]))


# --- GCM (NIST SP 800-38D), 96-bit nonces only --------------------------------

_GCM_REDUCTION = 0xE1 << 120


def _gcm_mul(x: int, y: int) -> int:
    """Multiply two 128-bit blocks in the GCM field GF(2^128)."""
    z = 0
    v = x
    for i in range(128):
        if (y >> (127 - i)) & 1:
            z ^= v
        if v & 1:
            v = (v >> 1) ^ _GCM_REDUCTION
        else:
            v >>= 1
    return z


def _inc32(block: int) -> int:
    return (block & ~0xFFFFFFFF) | ((block + 1) & 0xFFFFFFFF)


def _gctr(round_keys: list[bytes], icb: int, data: bytes) -> bytes:
    out = bytearray()
    counter = icb
    for off in range(0, len(data), 16):
        chunk = data[off : off + 16]
        stream = _encrypt_block(round_keys, counter.to_bytes(16, "big"))
        out.extend(a ^ b for a, b in zip(chunk, stream))
        counter = _inc32(counter)
    return bytes(out)


def _ghash(h: int, data: bytes) -> int:
    y = 0
    for off in range(0, len(data), 16):
        y = _gcm_mul(y ^ int.from_bytes(data[off : off + 16], "big"), h)
    return y


def _pad16(data: bytes) -> bytes:
    return data + b"\x00" * (-len(data) % 16)


def _ghash_input(aad: bytes, ciphertext: bytes) -> bytes:
    return _pad16(aad) + _pad16(ciphertext) + struct.pack(">QQ", len(aad) * 8, len(ciphertext) * 8)


def _aes_gcm_seal(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes) -> bytes:
    """Seal plaintext, returning ciphertext concatenated with the 16-byte tag."""
    round_keys = _expand_key(key)
    h = int.from_bytes(_encrypt_block(round_keys, b"\x00" * 16), "big")
    j0 = (int.from_bytes(nonce, "big") << 32) | 1
    ciphertext = _gctr(round_keys, _inc32(j0), plaintext)
    s = _ghash(h, _ghash_input(aad, ciphertext))
    tag = _gctr(round_keys, j0, s.to_bytes(16, "big"))
    return ciphertext + tag


def _aes_gcm_open(key: bytes, nonce: bytes, sealed: bytes, aad: bytes) -> bytes:
    """Open ciphertext||tag, raising InvalidCiphertext on any mismatch."""
    ciphertext, tag = sealed[:-_TAG_LEN], sealed[-_TAG_LEN:]
    round_keys = _expand_key(key)
    h = int.from_bytes(_encrypt_block(round_keys, b"\x00" * 16), "big")
    j0 = (int.from_bytes(nonce, "big") << 32) | 1
    s = _ghash(h, _ghash_input(aad, ciphertext))
    expected = _gctr(round_keys, j0, s.to_bytes(16, "big"))
    if not hmac.compare_digest(expected, tag):
        raise InvalidCiphertext("envelope authentication failed")
    return _gctr(round_keys, _inc32(j0), ciphertext)


# --- shared helpers ------------------------------------------------------------


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64url_decode(raw: Any, error: type[ValueError]) -> bytes:
    if not isinstance(raw, str) or not _BASE64URL_RE.fullmatch(raw):
        raise error("value must be an unpadded base64url string")
    # A length of 4n+1 cannot occur in valid (unpadded) base64.
    if len(raw) % 4 == 1:
        raise error("value must be an unpadded base64url string")
    padded = raw + "=" * (-len(raw) % 4)
    try:
        return base64.urlsafe_b64decode(padded.encode("ascii"))
    except (binascii.Error, ValueError):
        raise error("value must be an unpadded base64url string") from None


def _decode_secret(raw: Any) -> bytes:
    """Validate an unpadded base64url string decoding to exactly 32 bytes."""
    key = _b64url_decode(raw, InvalidKey)
    if len(key) != 32:
        raise InvalidKey("secret must decode to exactly 32 bytes")
    return key


def _validate_key_id(raw: Any, field: str = "key_id") -> str:
    if not isinstance(raw, str) or not raw:
        raise InvalidKey(f"{field} must be a non-empty string")
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
            raise InvalidKey("keys must map non-empty key ids to secrets")
        keys[key_id] = _decode_secret(secret)
    return keys


def _parse_pointer(item: Any) -> tuple[str, ...]:
    if not isinstance(item, str) or not item.startswith("/"):
        raise InvalidFields("each field must be a non-root JSON Pointer string starting with '/'")
    segments: list[str] = []
    for part in item.split("/")[1:]:
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
        pointers.append(segments)
    for i, first in enumerate(pointers):
        for second in pointers[i + 1 :]:
            shorter, longer = (first, second) if len(first) <= len(second) else (second, first)
            if longer[: len(shorter)] == shorter:
                raise InvalidFields("fields must not contain ancestor/descendant path pairs")
    return pointers


def _resolve(record: dict, segments: tuple[str, ...]) -> Any:
    """Resolve a JSON Pointer to its value, raising InvalidFields if absent."""
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


def _canonical_bytes(value: Any) -> bytes:
    """RFC 8785 canonical UTF-8 bytes of a JSON value."""
    try:
        return _canonicalize(value).encode("utf-8")
    except (InvalidAuditEvent, UnicodeEncodeError):
        raise InvalidFields("field values must be canonicalizable JSON") from None


def _aad(key_id: str, context: str, path: str) -> bytes:
    """Authentication data binding the key version, context and path."""
    parts = (key_id, context, path)
    return b"ev1" + b"".join(
        struct.pack(">I", len(part.encode("utf-8"))) + part.encode("utf-8") for part in parts
    )


def _seal_envelope(key: bytes, key_id: str, context: str, path: str, plaintext: bytes) -> dict:
    nonce = os.urandom(_NONCE_LEN)
    sealed = _aes_gcm_seal(key, nonce, plaintext, _aad(key_id, context, path))
    return {
        "alg": ALG,
        "key_id": key_id,
        "context": context,
        "nonce": _b64url_encode(nonce),
        "ciphertext": _b64url_encode(sealed),
    }


def _parse_envelope(value: Any) -> tuple[str, str, bytes, bytes]:
    """Validate an envelope, returning (key_id, context, nonce, ciphertext)."""
    if not isinstance(value, dict) or set(value) != _ENVELOPE_KEYS:
        raise InvalidEnvelope(
            "envelope must be an object with exactly alg, key_id, context, nonce and ciphertext"
        )
    if value["alg"] != ALG:
        raise InvalidEnvelope("envelope alg must be A256GCM")
    key_id = value["key_id"]
    if not isinstance(key_id, str) or not key_id:
        raise InvalidEnvelope("envelope key_id must be a non-empty string")
    context = value["context"]
    if not isinstance(context, str) or not context:
        raise InvalidEnvelope("envelope context must be a non-empty string")
    nonce = _b64url_decode(value["nonce"], InvalidEnvelope)
    if len(nonce) != _NONCE_LEN:
        raise InvalidEnvelope("envelope nonce must decode to 12 bytes")
    ciphertext = _b64url_decode(value["ciphertext"], InvalidEnvelope)
    if len(ciphertext) < _TAG_LEN:
        raise InvalidEnvelope("envelope ciphertext is too short")
    return key_id, context, nonce, ciphertext


def _open_envelope(envelope: tuple[str, str, bytes, bytes], keys: dict[str, bytes], path: str) -> bytes:
    key_id, context, nonce, ciphertext = envelope
    key = keys.get(key_id)
    if key is None:
        raise InvalidKey("envelope references a key_id missing from keys")
    return _aes_gcm_open(key, nonce, ciphertext, _aad(key_id, context, path))


def _resolve_all(records: list[dict], pointers: list[tuple[str, ...]]) -> None:
    for record in records:
        for segments in pointers:
            _resolve(record, segments)


def _parse_all_envelopes(
    records: list[dict], pointers: list[tuple[str, ...]]
) -> list[list[tuple[str, str, bytes, bytes]]]:
    per_record = []
    for record in records:
        per_record.append([_parse_envelope(_resolve(record, segments)) for segments in pointers])
    return per_record


# --- request handlers ----------------------------------------------------------


def encrypt_request(payload: Any) -> list[dict]:
    """Validate a /v1/encryption/encrypt payload and seal every target leaf."""
    records = _validate_records(payload)
    pointers = _validate_fields(payload.get("fields"))
    # Every pointer must resolve on every record before anything is
    # transformed — failures never return partial output.
    _resolve_all(records, pointers)
    key_id = _validate_key_id(payload.get("key_id"))
    key = _decode_secret(payload.get("secret"))
    context = _validate_context(payload.get("context"))

    paths = [_pointer(segments) for segments in pointers]
    results: list[dict] = []
    for index, record in enumerate(records):
        transformed = copy.deepcopy(record)
        for segments, path in zip(pointers, paths):
            plaintext = _canonical_bytes(_resolve(record, segments))
            _set_leaf(transformed, segments, _seal_envelope(key, key_id, context, path, plaintext))
        transformations = [{"path": path, "key_id": key_id} for path in sorted(paths)]
        results.append(
            {"index": index, "record": transformed, "transformations": transformations}
        )
    return results


def decrypt_request(payload: Any) -> list[dict]:
    """Validate a /v1/encryption/decrypt payload and restore every leaf."""
    records = _validate_records(payload)
    pointers = _validate_fields(payload.get("fields"))
    _resolve_all(records, pointers)
    keys = _validate_keys(payload.get("keys"))
    envelopes = _parse_all_envelopes(records, pointers)

    paths = [_pointer(segments) for segments in pointers]
    results: list[dict] = []
    for index, record in enumerate(records):
        restored = copy.deepcopy(record)
        used: dict[str, str] = {}
        for segments, path, envelope in zip(pointers, paths, envelopes[index]):
            plaintext = _open_envelope(envelope, keys, path)
            try:
                value = json.loads(plaintext.decode("utf-8"))
            except (UnicodeDecodeError, ValueError):
                raise InvalidCiphertext("envelope plaintext is not canonical JSON") from None
            _set_leaf(restored, segments, value)
            used[path] = envelope[0]
        transformations = [{"path": path, "key_id": used[path]} for path in sorted(paths)]
        results.append({"index": index, "record": restored, "transformations": transformations})
    return results


def rotate_request(payload: Any) -> list[dict]:
    """Validate a /v1/encryption/rotate payload and re-seal under a new key."""
    records = _validate_records(payload)
    pointers = _validate_fields(payload.get("fields"))
    _resolve_all(records, pointers)
    keys = _validate_keys(payload.get("keys"))
    new_key_id = _validate_key_id(payload.get("new_key_id"), "new_key_id")
    new_key = _decode_secret(payload.get("new_secret"))
    envelopes = _parse_all_envelopes(records, pointers)

    paths = [_pointer(segments) for segments in pointers]
    # Open every envelope before re-sealing anything — a rotation never
    # produces partially updated output.
    opened: list[list[tuple[str, str, bytes]]] = []
    for record_envelopes in envelopes:
        opened.append(
            [
                (envelope[0], envelope[1], _open_envelope(envelope, keys, path))
                for envelope, path in zip(record_envelopes, paths)
            ]
        )
    results: list[dict] = []
    for index, record in enumerate(records):
        rotated = copy.deepcopy(record)
        old_key_ids: dict[str, str] = {}
        for segments, path, (old_key_id, context, plaintext) in zip(pointers, paths, opened[index]):
            _set_leaf(
                rotated, segments, _seal_envelope(new_key, new_key_id, context, path, plaintext)
            )
            old_key_ids[path] = old_key_id
        transformations = [
            {"path": path, "old_key_id": old_key_ids[path], "new_key_id": new_key_id}
            for path in sorted(paths)
        ]
        results.append({"index": index, "record": rotated, "transformations": transformations})
    return results
