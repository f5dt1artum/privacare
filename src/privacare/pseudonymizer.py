"""Request-scoped, stateless pseudonymization for medical records.

Given a caller-supplied key (a base64url secret plus a key version id)
and a fixed set of JSON Pointer fields, every targeted non-empty string
leaf is replaced by a deterministic pseudonym

    pv1.<key_id>.<token>

where *token* is 43 unpadded base64url characters derived from an
HMAC-SHA256 over the key version, the context, the normalized pointer
path and the original value. The same inputs always yield the same
pseudonym (so cross-record linkability is preserved); changing any of
the secret, key id, context, path or value changes the token.

Like the other modules this is pure and request-scoped: the payload is
only read and never mutated, no records, keys or mappings are retained
between requests, and neither original values nor the secret are ever
echoed back.
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

from .classifier import (
    InvalidRequest,
    InvalidSchema,
    _parse_pointer,
    _pointer,
    _validate_records,
)

DEFAULT_CONTEXT = "privacare.pseudonymize.v1"

# Unpadded base64url (RFC 4648 section 5).
_BASE64URL_RE = re.compile(r"^[A-Za-z0-9_-]*$")

_MIN_KEY_BYTES = 32


class InvalidFields(ValueError):
    """The fields array is malformed or a pointer does not resolve to a leaf."""


class InvalidKey(ValueError):
    """key_id or secret is malformed."""


class InvalidContext(ValueError):
    """context is present but is not a non-empty string."""


def _decode_secret(raw: Any) -> bytes:
    if not isinstance(raw, str) or not raw or not _BASE64URL_RE.fullmatch(raw):
        raise InvalidKey("secret must be an unpadded base64url string")
    # A lone base64 character can never be a valid (unpadded) group.
    if len(raw) % 4 == 1:
        raise InvalidKey("secret must be an unpadded base64url string")
    try:
        key = base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4))
    except (binascii.Error, ValueError) as exc:
        raise InvalidKey("secret must be an unpadded base64url string") from exc
    if len(key) < _MIN_KEY_BYTES:
        raise InvalidKey("secret must decode to at least 32 bytes")
    return key


def _validate_key_id(raw: Any) -> str:
    if not isinstance(raw, str) or not raw:
        raise InvalidKey("key_id must be a non-empty string")
    return raw


def _validate_context(raw: Any) -> str:
    if raw is None:
        return DEFAULT_CONTEXT
    if not isinstance(raw, str) or not raw:
        raise InvalidContext("context must be a non-empty string when present")
    return raw


def _validate_fields(raw: Any) -> list[tuple[str, ...]]:
    if not isinstance(raw, list) or not raw:
        raise InvalidFields("fields must be a non-empty array of JSON Pointer strings")
    pointers: list[tuple[str, ...]] = []
    seen: set[str] = set()
    for item in raw:
        if not isinstance(item, str):
            raise InvalidFields("fields must be JSON Pointer strings")
        try:
            segments = _parse_pointer(item)
        except InvalidSchema as exc:
            raise InvalidFields("fields must contain valid JSON Pointer strings") from exc
        if item in seen:
            raise InvalidFields("fields must not contain duplicates")
        seen.add(item)
        pointers.append(segments)
    return pointers


def _resolve_string_leaf(record: dict, segments: tuple[str, ...]) -> str:
    """Resolve a pointer, requiring the target to be a non-empty string leaf.

    Array index handling follows RFC 6901: "0" alone may have a leading
    zero, every other index may not, and "-" never resolves.
    """
    node: Any = record
    for segment in segments:
        if isinstance(node, dict):
            if segment not in node:
                raise InvalidFields("every field pointer must resolve on every record")
            node = node[segment]
        elif isinstance(node, list):
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
    if not isinstance(node, str) or not node:
        raise InvalidFields("field pointers must resolve to non-empty string leaves")
    return node


def _token(key: bytes, key_id: str, context: str, path: str, value: str) -> str:
    """Derive the 43-char unpadded base64url token for one value.

    Each component is length-prefixed (8-byte big-endian byte length) so
    the encoding is injective regardless of what the strings contain:
    no separator can ever be confused with field data.
    """
    parts = (key_id, context, path, value)
    message = b"".join(
        struct.pack(">Q", len(blob)) + blob
        for blob in (part.encode("utf-8") for part in parts)
    )
    digest = hmac.new(key, message, hashlib.sha256).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _replace_leaf(record: Any, segments: tuple[str, ...], value: Any) -> None:
    for segment in segments[:-1]:
        record = record[int(segment)] if isinstance(record, list) else record[segment]
    last = segments[-1]
    if isinstance(record, list):
        record[int(last)] = value
    else:
        record[last] = value


def pseudonymize_request(payload: Any) -> list[dict]:
    """Validate a /v1/pseudonymize payload and pseudonymize every record."""
    records = _validate_records(payload)
    fields = _validate_fields(payload.get("fields"))
    key_id = _validate_key_id(payload.get("key_id"))
    key = _decode_secret(payload.get("secret"))
    context = _validate_context(payload.get("context"))

    # Resolve every field on every record before copying anything, so a
    # single failure never produces partial results or mutations.
    paths = [_pointer(segments) for segments in fields]
    planned: list[list[tuple[str, str]]] = []
    for record in records:
        replacements: list[tuple[str, str]] = []
        for segments, path in zip(fields, paths):
            original = _resolve_string_leaf(record, segments)
            pseudonym = f"pv1.{key_id}.{_token(key, key_id, context, path, original)}"
            replacements.append((path, pseudonym))
        planned.append(replacements)

    results: list[dict] = []
    for index, (record, replacements) in enumerate(zip(records, planned)):
        transformed = copy.deepcopy(record)
        transformations = []
        for segments, (path, pseudonym) in zip(fields, replacements):
            _replace_leaf(transformed, segments, pseudonym)
            transformations.append({"path": path, "key_id": key_id})
        transformations.sort(key=lambda item: item["path"])
        results.append(
            {"index": index, "record": transformed, "transformations": transformations}
        )
    return results
