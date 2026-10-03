"""Deterministic, request-scoped pseudonymization for medical records.

Pseudonyms preserve cross-record linkage without retaining any mapping:
the token for a leaf is an HMAC-SHA256 of the original value under the
request secret, bound to the key version, a context and the leaf's
canonical JSON Pointer. Everything is derived from the current request
only — the caller's data is never mutated, no record, key or mapping is
kept between requests, and identical inputs always produce identical
pseudonyms.
"""

from __future__ import annotations

import base64
import binascii
import copy
import hashlib
import hmac
import re
import struct
from typing import Any

from .classifier import InvalidRequest, _pointer, _validate_records

#: Context used when the caller does not supply one.
DEFAULT_CONTEXT = "privacare.pseudonymize.v1"

_BASE64URL_RE = re.compile(r"^[A-Za-z0-9_-]+$")


class InvalidFields(ValueError):
    """The fields array or one of its pointer targets is malformed."""


class InvalidKey(ValueError):
    """The key_id or secret is malformed."""


class InvalidContext(ValueError):
    """The context is malformed."""


def _decode_secret(raw: Any) -> bytes:
    """Validate an unpadded base64url string decoding to at least 32 bytes."""
    if not isinstance(raw, str) or not _BASE64URL_RE.fullmatch(raw):
        raise InvalidKey("secret must be an unpadded base64url string")
    # A length of 4n+1 cannot occur in valid (unpadded) base64.
    if len(raw) % 4 == 1:
        raise InvalidKey("secret must be an unpadded base64url string")
    padded = raw + "=" * (-len(raw) % 4)
    try:
        key = base64.urlsafe_b64decode(padded.encode("ascii"))
    except (binascii.Error, ValueError):
        raise InvalidKey("secret must be an unpadded base64url string") from None
    if len(key) < 32:
        raise InvalidKey("secret must decode to at least 32 bytes")
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


def _validate_fields(raw: Any) -> list[tuple[str, ...]]:
    if not isinstance(raw, list) or not raw:
        raise InvalidFields("fields must be a non-empty array of JSON Pointer strings")
    pointers: list[tuple[str, ...]] = []
    seen: set[str] = set()
    for item in raw:
        if not isinstance(item, str) or not item.startswith("/"):
            raise InvalidFields("each field must be a JSON Pointer string starting with '/'")
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
        if item in seen:
            raise InvalidFields("fields must not contain duplicates")
        seen.add(item)
        pointers.append(tuple(segments))
    return pointers


def _resolve_leaf(record: dict, segments: tuple[str, ...]) -> str:
    """Resolve a JSON Pointer to a non-empty string leaf."""
    node: Any = record
    for depth, segment in enumerate(segments):
        last = depth == len(segments) - 1
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
        if last and (not isinstance(node, str) or not node):
            raise InvalidFields("field pointers must resolve to non-empty string leaves")
    return node


def _token(key: bytes, key_id: str, context: str, path: str, value: str) -> str:
    """Derive the 43-char unpadded base64url token for one value."""
    parts = (key_id, context, path, value)
    message = b"pv1" + b"".join(
        struct.pack(">I", len(part.encode("utf-8"))) + part.encode("utf-8") for part in parts
    )
    digest = hmac.new(key, message, hashlib.sha256).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _set_leaf(node: Any, segments: tuple[str, ...], value: str) -> None:
    for segment in segments[:-1]:
        node = node[int(segment)] if isinstance(node, list) else node[segment]
    last = segments[-1]
    if isinstance(node, list):
        node[int(last)] = value
    else:
        node[last] = value


def pseudonymize_request(payload: Any) -> list[dict]:
    """Validate a /v1/pseudonymize payload and pseudonymize every record."""
    records = _validate_records(payload)
    pointers = _validate_fields(payload.get("fields"))
    # Every pointer must resolve to a non-empty string leaf on every record
    # before anything is transformed — failures never return partial output.
    for record in records:
        for segments in pointers:
            _resolve_leaf(record, segments)
    key_id = _validate_key_id(payload.get("key_id"))
    key = _decode_secret(payload.get("secret"))
    context = _validate_context(payload.get("context"))

    paths = [_pointer(segments) for segments in pointers]
    results: list[dict] = []
    for index, record in enumerate(records):
        transformed = copy.deepcopy(record)
        token_cache: dict[tuple[str, str], str] = {}
        for segments, path in zip(pointers, paths):
            original = _resolve_leaf(record, segments)
            cache_key = (path, original)
            token = token_cache.get(cache_key)
            if token is None:
                token = _token(key, key_id, context, path, original)
                token_cache[cache_key] = token
            _set_leaf(transformed, segments, f"pv1.{key_id}.{token}")
        transformations = [{"path": path, "key_id": key_id} for path in sorted(paths)]
        results.append(
            {"index": index, "record": transformed, "transformations": transformations}
        )
    return results
