"""Tamper-evident audit evidence chains.

Pure and request-scoped like the other modules: events, anchors and
evidence are read from the current payload only, nothing is persisted
between requests, the caller's data is never mutated, and identical
inputs always produce identical results. Events are hashed under RFC
8785 (JSON Canonicalization Scheme) so chains inter-operate across
stacks, and each step computes SHA-256 over the previous hash bytes
concatenated with the canonical UTF-8 bytes of the event.
"""

from __future__ import annotations

import hashlib
import math
import re
from datetime import datetime
from typing import Any

from .classifier import InvalidRequest

ZERO_ANCHOR = "0" * 64

OUTCOMES: tuple[str, ...] = ("allowed", "denied")

_HASH_RE = re.compile(r"^[0-9a-fA-F]{64}$")

# RFC 3339 date-time with a mandatory numeric offset or "Z".
_RFC3339_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$"
)

_REQUIRED_FIELDS = (
    "event_id",
    "occurred_at",
    "actor_id",
    "action",
    "resource",
    "purpose",
    "outcome",
)
_STRING_FIELDS = ("event_id", "actor_id", "action", "resource", "purpose")
_EVIDENCE_FIELDS = ("index", "event_id", "previous_hash", "evidence_hash")


class InvalidAuditEvent(ValueError):
    """An audit event is malformed."""


class InvalidAnchor(ValueError):
    """The anchor hash is malformed."""


class InvalidEvidenceChain(ValueError):
    """The supplied evidence chain is malformed."""


# --- RFC 8785 (JSON Canonicalization Scheme) -------------------------------

_ESCAPES = {
    '"': '\\"',
    "\\": "\\\\",
    "\b": "\\b",
    "\t": "\\t",
    "\n": "\\n",
    "\f": "\\f",
    "\r": "\\r",
}


def _quote(text: str) -> str:
    out = ['"']
    for ch in text:
        escape = _ESCAPES.get(ch)
        if escape is not None:
            out.append(escape)
        elif ord(ch) < 0x20:
            out.append(f"\\u{ord(ch):04x}")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _sort_key(key: str) -> bytes:
    """Object keys sort by UTF-16 code units, not code points."""
    return key.encode("utf-16-be", "surrogatepass")


def _format_float(value: float) -> str:
    """ECMAScript Number::toString for a finite double."""
    if math.isnan(value) or math.isinf(value):
        raise InvalidAuditEvent("event numbers must be finite")
    if value == 0:
        return "0"
    sign = ""
    if value < 0:
        sign = "-"
        value = -value
    text = repr(value)  # shortest round-trip digits
    if "e" in text:
        mantissa, exp_text = text.split("e")
        exponent = int(exp_text)
    else:
        mantissa, exponent = text, 0
    if "." in mantissa:
        int_part, frac_part = mantissa.split(".")
    else:
        int_part, frac_part = mantissa, ""
    # value == int(digits) * 10**scale; normalize digits to the shortest
    # form (no leading/trailing zeros) the ECMAScript algorithm assumes.
    scale = exponent - len(frac_part)
    digits = (int_part + frac_part).lstrip("0")
    stripped = digits.rstrip("0")
    scale += len(digits) - len(stripped)
    digits = stripped
    k = len(digits)
    n = scale + k  # value == 0.digits * 10**n
    if k <= n <= 21:
        return sign + digits + "0" * (n - k)
    if 0 < n <= 21:
        return sign + digits[:n] + "." + digits[n:]
    if -6 < n <= 0:
        return sign + "0." + "0" * (-n) + digits
    mantissa_out = digits[0] + ("." + digits[1:] if k > 1 else "")
    exponent_out = n - 1
    return f"{sign}{mantissa_out}e{'+' if exponent_out >= 0 else '-'}{abs(exponent_out)}"


def _number(value: int | float) -> str:
    if isinstance(value, int):
        if abs(value) < 10**21:
            return str(value)
        try:
            value = float(value)
        except OverflowError:
            raise InvalidAuditEvent("event numbers must be finite") from None
    return _format_float(value)


def _canonicalize(value: Any) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, str):
        return _quote(value)
    if isinstance(value, (int, float)):
        return _number(value)
    if isinstance(value, list):
        return "[" + ",".join(_canonicalize(item) for item in value) + "]"
    if isinstance(value, dict):
        parts = []
        for key, item in sorted(value.items(), key=lambda kv: _sort_key(kv[0])):
            if not isinstance(key, str):
                raise InvalidAuditEvent("event object keys must be strings")
            parts.append(_quote(key) + ":" + _canonicalize(item))
        return "{" + ",".join(parts) + "}"
    raise InvalidAuditEvent("events must contain only JSON values")


def _canonical_bytes(event: dict) -> bytes:
    try:
        return _canonicalize(event).encode("utf-8")
    except UnicodeEncodeError:
        raise InvalidAuditEvent("event strings must be valid Unicode") from None


# --- validation ------------------------------------------------------------


def _parse_occurred_at(raw: Any) -> None:
    """Require an RFC 3339 timestamp that carries a timezone offset."""
    if not isinstance(raw, str) or not _RFC3339_RE.match(raw):
        raise InvalidAuditEvent("occurred_at must be an RFC 3339 date-time with a timezone offset")
    text = raw[:-1] + "+00:00" if raw.endswith("Z") else raw
    try:
        datetime.fromisoformat(text)
    except ValueError:
        raise InvalidAuditEvent("occurred_at must be a valid RFC 3339 date-time") from None


def _validate_event(raw: Any) -> None:
    if not isinstance(raw, dict):
        raise InvalidAuditEvent("each event must be an object")
    for field in _REQUIRED_FIELDS:
        if field not in raw:
            raise InvalidAuditEvent(f"event is missing {field}")
    for field in _STRING_FIELDS:
        value = raw[field]
        if not isinstance(value, str) or not value:
            raise InvalidAuditEvent(f"{field} must be a non-empty string")
    _parse_occurred_at(raw["occurred_at"])
    outcome = raw["outcome"]
    if not isinstance(outcome, str) or outcome not in OUTCOMES:
        raise InvalidAuditEvent("outcome must be 'allowed' or 'denied'")
    if "details" in raw and not isinstance(raw["details"], dict):
        raise InvalidAuditEvent("details must be an object when present")


def _validate_events(payload: Any) -> list:
    if not isinstance(payload, dict):
        raise InvalidRequest("request body must be a JSON object")
    events = payload.get("events")
    if not isinstance(events, list) or not events:
        raise InvalidRequest("events must be a non-empty array")
    seen_ids: set[str] = set()
    for event in events:
        _validate_event(event)
        event_id = event["event_id"]
        if event_id in seen_ids:
            raise InvalidAuditEvent("event_id must be unique within the request")
        seen_ids.add(event_id)
    return events


def _parse_anchor(raw: Any) -> str:
    if raw is None:
        return ZERO_ANCHOR
    if not isinstance(raw, str) or not _HASH_RE.fullmatch(raw):
        raise InvalidAnchor("anchor_hash must be a 64-character hexadecimal string")
    return raw.lower()


def _validate_evidence(raw: Any, expected_length: int) -> list:
    if not isinstance(raw, list) or len(raw) != expected_length:
        raise InvalidEvidenceChain("evidence must be an array with one entry per event")
    for entry in raw:
        if not isinstance(entry, dict):
            raise InvalidEvidenceChain("each evidence entry must be an object")
        for field in _EVIDENCE_FIELDS:
            if field not in entry:
                raise InvalidEvidenceChain(f"evidence entry is missing {field}")
        for field in ("previous_hash", "evidence_hash"):
            value = entry[field]
            if not isinstance(value, str) or not _HASH_RE.fullmatch(value):
                raise InvalidEvidenceChain(f"{field} must be a 64-character hexadecimal string")
    return raw


# --- chain building and verification ---------------------------------------


def _build_chain(events: list, anchor: str) -> tuple[list[dict], str]:
    previous = bytes.fromhex(anchor)
    evidence = []
    for index, event in enumerate(events):
        digest = hashlib.sha256(previous + _canonical_bytes(event)).hexdigest()
        evidence.append(
            {
                "index": index,
                "event_id": event["event_id"],
                "previous_hash": previous.hex(),
                "evidence_hash": digest,
            }
        )
        previous = bytes.fromhex(digest)
    return evidence, previous.hex()


def audit_chain_request(payload: Any) -> dict:
    """Validate a /v1/audit/chain payload and build the evidence chain."""
    events = _validate_events(payload)
    anchor = _parse_anchor(payload.get("anchor_hash"))
    evidence, final_hash = _build_chain(events, anchor)
    return {"anchor_hash": anchor, "final_hash": final_hash, "evidence": evidence}


def audit_verify_request(payload: Any) -> dict:
    """Validate a /v1/audit/verify payload and recompute the chain."""
    events = _validate_events(payload)
    anchor = _parse_anchor(payload.get("anchor_hash"))
    evidence = _validate_evidence(payload.get("evidence"), len(events))
    expected, _final_hash = _build_chain(events, anchor)
    for index, (want, got) in enumerate(zip(expected, evidence)):
        if (
            got["index"] != want["index"]
            or got["event_id"] != want["event_id"]
            or got["previous_hash"].lower() != want["previous_hash"]
            or got["evidence_hash"].lower() != want["evidence_hash"]
        ):
            return {"valid": False, "first_invalid_index": index}
    return {"valid": True, "first_invalid_index": None}
