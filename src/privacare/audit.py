"""Tamper-evident audit evidence chains.

Pure and request-scoped like the other modules: events, the anchor and any
prior evidence are read from the current payload only, nothing is persisted
between requests, the caller's data is never mutated, and identical inputs
always produce identical results. Each evidence hash chains the previous
hash (raw bytes) with the event serialized per RFC 8785 (JSON Canonical
Serialization) using SHA-256, so callers can carry one batch's final_hash
into the next batch's anchor_hash.
"""

from __future__ import annotations

import hashlib
import math
import re
from datetime import datetime
from typing import Any

from .classifier import InvalidRequest

ZERO_HASH = "0" * 64

OUTCOMES: tuple[str, ...] = ("allowed", "denied")

_EVENT_FIELDS = (
    "event_id",
    "occurred_at",
    "actor_id",
    "action",
    "resource",
    "purpose",
    "outcome",
)

_EVENT_STRING_FIELDS = ("event_id", "actor_id", "action", "resource", "purpose")

_EVIDENCE_FIELDS = ("index", "event_id", "previous_hash", "evidence_hash")

_HEX64_RE = re.compile(r"^[0-9a-fA-F]{64}$")

# RFC 3339 date-time with a mandatory numeric offset or "Z".
_RFC3339_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$"
)


class InvalidAuditEvent(ValueError):
    """An audit event is malformed."""


class InvalidAnchor(ValueError):
    """The supplied anchor_hash is malformed."""


class InvalidEvidenceChain(ValueError):
    """The supplied evidence array is malformed."""


# --- RFC 8785 (JCS) canonical serialization ---------------------------------

_ESCAPES = {
    '"': '\\"',
    "\\": "\\\\",
    "\b": "\\b",
    "\t": "\\t",
    "\n": "\\n",
    "\f": "\\f",
    "\r": "\\r",
}


def _serialize_string(value: str) -> str:
    parts = ['"']
    for char in value:
        escape = _ESCAPES.get(char)
        if escape is not None:
            parts.append(escape)
        elif ord(char) < 0x20:
            parts.append(f"\\u{ord(char):04x}")
        else:
            parts.append(char)
    parts.append('"')
    return "".join(parts)


def _serialize_number(value: int | float) -> str:
    """ECMAScript Number::toString as required by RFC 8785."""
    if isinstance(value, int):
        return str(value)
    if not math.isfinite(value):
        raise InvalidAuditEvent("numbers must be finite")
    if value == 0:
        return "0"
    mantissa, _, exp_text = repr(value).partition("e")
    exponent = int(exp_text) if exp_text else 0
    negative = mantissa.startswith("-")
    mantissa = mantissa.lstrip("-")
    integer, _, fraction = mantissa.partition(".")
    digits = integer + fraction
    point = len(integer) + exponent
    stripped = digits.lstrip("0")
    point -= len(digits) - len(stripped)
    digits = stripped.rstrip("0") or "0"
    if -6 < point <= 21:
        if point <= 0:
            text = "0." + "0" * (-point) + digits
        elif point >= len(digits):
            text = digits + "0" * (point - len(digits))
        else:
            text = digits[:point] + "." + digits[point:]
    else:
        head = digits[0]
        if len(digits) > 1:
            head += "." + digits[1:]
        shift = point - 1
        text = head + "e" + ("+" if shift >= 0 else "-") + str(abs(shift))
    return ("-" if negative else "") + text


def _serialize(value: Any) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, str):
        return _serialize_string(value)
    if isinstance(value, (int, float)):
        return _serialize_number(value)
    if isinstance(value, list):
        return "[" + ",".join(_serialize(item) for item in value) + "]"
    if isinstance(value, dict):
        keys = sorted(value, key=lambda key: key.encode("utf-16-be", "surrogatepass"))
        return "{" + ",".join(
            _serialize_string(key) + ":" + _serialize(value[key]) for key in keys
        ) + "}"
    raise InvalidAuditEvent("events must contain only JSON values")


def _canonical_bytes(value: Any) -> bytes:
    return _serialize(value).encode("utf-8")


# --- validation ---------------------------------------------------------------

def _parse_time(raw: Any) -> datetime:
    """Parse an RFC 3339 timestamp that must carry a timezone offset."""
    if not isinstance(raw, str) or not _RFC3339_RE.match(raw):
        raise InvalidAuditEvent(
            "occurred_at must be an RFC 3339 date-time with a timezone offset"
        )
    text = raw[:-1] + "+00:00" if raw.endswith("Z") else raw
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        raise InvalidAuditEvent(
            "occurred_at must be a valid RFC 3339 date-time"
        ) from None


def _validate_event(raw: Any, seen_ids: set[str]) -> None:
    if not isinstance(raw, dict):
        raise InvalidAuditEvent("each event must be an object")
    for field in _EVENT_FIELDS:
        if field not in raw:
            raise InvalidAuditEvent(f"event is missing {field}")
    for field in _EVENT_STRING_FIELDS:
        value = raw[field]
        if not isinstance(value, str) or not value:
            raise InvalidAuditEvent(f"{field} must be a non-empty string")
    event_id = raw["event_id"]
    if event_id in seen_ids:
        raise InvalidAuditEvent("event_id must be unique within the request")
    seen_ids.add(event_id)
    _parse_time(raw["occurred_at"])
    outcome = raw["outcome"]
    if not isinstance(outcome, str) or outcome not in OUTCOMES:
        raise InvalidAuditEvent("outcome must be 'allowed' or 'denied'")
    if "details" in raw and not isinstance(raw["details"], dict):
        raise InvalidAuditEvent("details must be an object when present")


def _validate_events(payload: Any) -> list[dict]:
    if not isinstance(payload, dict):
        raise InvalidRequest("request body must be a JSON object")
    raw_events = payload.get("events")
    if not isinstance(raw_events, list) or not raw_events:
        raise InvalidRequest("events must be a non-empty array")
    seen_ids: set[str] = set()
    for raw in raw_events:
        _validate_event(raw, seen_ids)
    return raw_events


def _parse_anchor(payload: dict) -> str:
    if "anchor_hash" not in payload:
        return ZERO_HASH
    raw = payload["anchor_hash"]
    if not isinstance(raw, str) or not _HEX64_RE.match(raw):
        raise InvalidAnchor("anchor_hash must be a 64-character hexadecimal string")
    return raw.lower()


def _validate_evidence_entry(raw: Any) -> dict:
    if not isinstance(raw, dict):
        raise InvalidEvidenceChain("each evidence entry must be an object")
    for field in _EVIDENCE_FIELDS:
        if field not in raw:
            raise InvalidEvidenceChain(f"evidence entry is missing {field}")
    for field in ("previous_hash", "evidence_hash"):
        value = raw[field]
        if not isinstance(value, str) or not _HEX64_RE.match(value):
            raise InvalidEvidenceChain(
                f"{field} must be a 64-character hexadecimal string"
            )
    return raw


def _hash_event(previous_hash: str, event: dict) -> str:
    return hashlib.sha256(
        bytes.fromhex(previous_hash) + _canonical_bytes(event)
    ).hexdigest()


# --- public entry points ------------------------------------------------------

def audit_chain_request(payload: Any) -> dict:
    """Build a tamper-evident evidence chain for a /v1/audit/chain payload."""
    events = _validate_events(payload)
    anchor = _parse_anchor(payload)
    evidence: list[dict] = []
    previous = anchor
    for index, event in enumerate(events):
        digest = _hash_event(previous, event)
        evidence.append(
            {
                "index": index,
                "event_id": event["event_id"],
                "previous_hash": previous,
                "evidence_hash": digest,
            }
        )
        previous = digest
    return {"anchor_hash": anchor, "final_hash": previous, "evidence": evidence}


def audit_verify_request(payload: Any) -> dict:
    """Recompute and check a chain for a /v1/audit/verify payload."""
    events = _validate_events(payload)
    anchor = _parse_anchor(payload)
    raw_evidence = payload.get("evidence")
    if not isinstance(raw_evidence, list) or len(raw_evidence) != len(events):
        raise InvalidEvidenceChain(
            "evidence must be an array with one entry per event"
        )
    entries = [_validate_evidence_entry(raw) for raw in raw_evidence]
    previous = anchor
    for index, (event, entry) in enumerate(zip(events, entries)):
        expected = _hash_event(previous, event)
        if (
            entry["index"] != index
            or entry["event_id"] != event["event_id"]
            or entry["previous_hash"].lower() != previous
            or entry["evidence_hash"].lower() != expected
        ):
            return {"valid": False, "first_invalid_index": index}
        previous = expected
    return {"valid": True, "first_invalid_index": None}
