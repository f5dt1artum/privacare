"""Request-level consent and purpose-constraint evaluation.

Pure and request-scoped like the other modules: consents and accesses are
read from the current payload only, nothing is persisted between requests,
the caller's data is never mutated, and identical inputs always produce
identical results.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

from .classifier import CATEGORIES, InvalidRequest

STATUSES: tuple[str, ...] = ("active", "revoked")

EVENT_TYPES: tuple[str, ...] = ("grant", "amend", "revoke")

TIMELINE_STATUSES: tuple[str, ...] = ("not_found", "pending", "active", "expired", "revoked")

_CATEGORY_SET = frozenset(CATEGORIES)
_STATUS_SET = frozenset(STATUSES)
_EVENT_TYPE_SET = frozenset(EVENT_TYPES)

_CONSENT_FIELDS = (
    "consent_id",
    "subject_id",
    "purposes",
    "data_categories",
    "recipients",
    "valid_from",
    "valid_until",
    "status",
)

_ACCESS_FIELDS = (
    "subject_id",
    "purpose",
    "data_category",
    "recipient",
    "requested_at",
)

# RFC 3339 date-time with a mandatory numeric offset or "Z".
_RFC3339_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$"
)


class InvalidConsent(ValueError):
    """A consent entry is malformed."""


class InvalidAccess(ValueError):
    """An access entry is malformed."""


class InvalidConsentEvent(ValueError):
    """A consent lifecycle event is malformed."""


class InvalidConsentQuery(ValueError):
    """A consent timeline query is malformed."""


def _parse_time(raw: Any, error: type[ValueError]) -> datetime:
    """Parse an RFC 3339 timestamp that must carry a timezone offset."""
    if not isinstance(raw, str) or not _RFC3339_RE.match(raw):
        raise error("timestamps must be RFC 3339 date-times with a timezone offset")
    text = raw[:-1] + "+00:00" if raw.endswith("Z") else raw
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        raise error("timestamps must be valid RFC 3339 date-times") from None


def _require_string(entry: dict, field: str, error: type[ValueError]) -> str:
    value = entry.get(field)
    if not isinstance(value, str) or not value:
        raise error(f"{field} must be a non-empty string")
    return value


def _require_string_set(entry: dict, field: str, error: type[ValueError]) -> frozenset[str]:
    value = entry.get(field)
    if not isinstance(value, list) or not value:
        raise error(f"{field} must be a non-empty array")
    seen: set[str] = set()
    for item in value:
        if not isinstance(item, str) or not item:
            raise error(f"{field} must contain only non-empty strings")
        if item in seen:
            raise error(f"{field} must not contain duplicates")
        seen.add(item)
    return frozenset(value)


def _parse_consent(raw: Any) -> dict:
    if not isinstance(raw, dict):
        raise InvalidConsent("each consent must be an object")
    for field in _CONSENT_FIELDS:
        if field not in raw:
            raise InvalidConsent(f"consent is missing {field}")
    consent_id = _require_string(raw, "consent_id", InvalidConsent)
    subject_id = _require_string(raw, "subject_id", InvalidConsent)
    purposes = _require_string_set(raw, "purposes", InvalidConsent)
    data_categories = _require_string_set(raw, "data_categories", InvalidConsent)
    if not data_categories <= _CATEGORY_SET:
        raise InvalidConsent("data_categories contains an unsupported category")
    recipients = _require_string_set(raw, "recipients", InvalidConsent)
    status = raw["status"]
    if not isinstance(status, str) or status not in _STATUS_SET:
        raise InvalidConsent("status must be 'active' or 'revoked'")
    valid_from = _parse_time(raw["valid_from"], InvalidConsent)
    valid_until = _parse_time(raw["valid_until"], InvalidConsent)
    if valid_until <= valid_from:
        raise InvalidConsent("valid_until must be later than valid_from")
    return {
        "consent_id": consent_id,
        "subject_id": subject_id,
        "purposes": purposes,
        "data_categories": data_categories,
        "recipients": recipients,
        "valid_from": valid_from,
        "valid_until": valid_until,
        "status": status,
    }


def _parse_access(raw: Any) -> dict:
    if not isinstance(raw, dict):
        raise InvalidAccess("each access must be an object")
    for field in _ACCESS_FIELDS:
        if field not in raw:
            raise InvalidAccess(f"access is missing {field}")
    subject_id = _require_string(raw, "subject_id", InvalidAccess)
    purpose = _require_string(raw, "purpose", InvalidAccess)
    recipient = _require_string(raw, "recipient", InvalidAccess)
    data_category = raw["data_category"]
    if not isinstance(data_category, str) or data_category not in _CATEGORY_SET:
        raise InvalidAccess("data_category is not a supported category")
    requested_at = _parse_time(raw["requested_at"], InvalidAccess)
    return {
        "subject_id": subject_id,
        "purpose": purpose,
        "data_category": data_category,
        "recipient": recipient,
        "requested_at": requested_at,
    }


def _covers(consent: dict, access: dict) -> bool:
    """Whether one active consent authorizes one access."""
    return (
        consent["status"] == "active"
        and consent["subject_id"] == access["subject_id"]
        and access["purpose"] in consent["purposes"]
        and access["data_category"] in consent["data_categories"]
        and access["recipient"] in consent["recipients"]
        and consent["valid_from"] <= access["requested_at"] < consent["valid_until"]
    )


def _select(consents: list[dict], access: dict) -> dict | None:
    """Pick the covering consent with the latest valid_from, breaking ties
    by the lexicographically smallest consent_id."""
    best: dict | None = None
    for consent in consents:
        if not _covers(consent, access):
            continue
        if best is None or (consent["valid_from"], best["consent_id"]) > (
            best["valid_from"],
            consent["consent_id"],
        ):
            best = consent
    return best


def consent_evaluate_request(payload: Any) -> list[dict]:
    """Validate a /v1/consent/evaluate payload and rule on every access."""
    if not isinstance(payload, dict):
        raise InvalidRequest("request body must be a JSON object")
    raw_consents = payload.get("consents")
    if not isinstance(raw_consents, list) or not raw_consents:
        raise InvalidRequest("consents must be a non-empty array")
    raw_accesses = payload.get("accesses")
    if not isinstance(raw_accesses, list) or not raw_accesses:
        raise InvalidRequest("accesses must be a non-empty array")

    consents = [_parse_consent(raw) for raw in raw_consents]
    seen_ids: set[str] = set()
    for consent in consents:
        if consent["consent_id"] in seen_ids:
            raise InvalidConsent("consent_id must be unique within the request")
        seen_ids.add(consent["consent_id"])
    accesses = [_parse_access(raw) for raw in raw_accesses]

    results: list[dict] = []
    for index, access in enumerate(accesses):
        consent = _select(consents, access)
        if consent is None:
            results.append({"index": index, "allowed": False, "reason": "no_matching_consent"})
        else:
            results.append(
                {
                    "index": index,
                    "allowed": True,
                    "reason": "consent_granted",
                    "consent_id": consent["consent_id"],
                }
            )
    return results


# --- Request-level consent lifecycle timelines -----------------------------

_EVENT_FIELDS = ("event_id", "consent_id", "version", "occurred_at", "type")

# Fields that carry the consent scope and validity window. A grant also
# carries subject_id; an amend inherits it; a revoke carries none of these.
_SCOPE_FIELDS = ("purposes", "data_categories", "recipients")
_VALIDITY_FIELDS = ("valid_from", "valid_until")
_STATE_FIELDS = ("subject_id",) + _SCOPE_FIELDS + _VALIDITY_FIELDS

_QUERY_FIELDS = ("consent_id", "as_of")


def _format_time(value: datetime) -> str:
    """Render a parsed timestamp as an RFC 3339 UTC date-time."""
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _parse_scope_and_validity(raw: dict) -> dict:
    """Parse the scope arrays and validity window shared by grant/amend."""
    purposes = _require_string_set(raw, "purposes", InvalidConsentEvent)
    data_categories = _require_string_set(raw, "data_categories", InvalidConsentEvent)
    if not data_categories <= _CATEGORY_SET:
        raise InvalidConsentEvent("data_categories contains an unsupported category")
    recipients = _require_string_set(raw, "recipients", InvalidConsentEvent)
    valid_from = _parse_time(raw.get("valid_from"), InvalidConsentEvent)
    valid_until = _parse_time(raw.get("valid_until"), InvalidConsentEvent)
    if valid_until <= valid_from:
        raise InvalidConsentEvent("valid_until must be later than valid_from")
    return {
        "purposes": purposes,
        "data_categories": data_categories,
        "recipients": recipients,
        "valid_from": valid_from,
        "valid_until": valid_until,
    }


def _parse_event(raw: Any) -> dict:
    if not isinstance(raw, dict):
        raise InvalidConsentEvent("each event must be an object")
    for field in _EVENT_FIELDS:
        if field not in raw:
            raise InvalidConsentEvent(f"event is missing {field}")
    event_id = _require_string(raw, "event_id", InvalidConsentEvent)
    consent_id = _require_string(raw, "consent_id", InvalidConsentEvent)
    version = raw["version"]
    if not isinstance(version, int) or isinstance(version, bool) or version < 1:
        raise InvalidConsentEvent("version must be a positive integer")
    occurred_at = _parse_time(raw["occurred_at"], InvalidConsentEvent)
    event_type = raw["type"]
    if not isinstance(event_type, str) or event_type not in _EVENT_TYPE_SET:
        raise InvalidConsentEvent("type must be 'grant', 'amend' or 'revoke'")
    event = {
        "event_id": event_id,
        "consent_id": consent_id,
        "version": version,
        "occurred_at": occurred_at,
        "type": event_type,
    }
    if event_type == "grant":
        if version != 1:
            raise InvalidConsentEvent("grant must be version 1")
        event["subject_id"] = _require_string(raw, "subject_id", InvalidConsentEvent)
        event.update(_parse_scope_and_validity(raw))
    elif event_type == "amend":
        if "subject_id" in raw:
            raise InvalidConsentEvent("amend must not carry subject_id")
        event.update(_parse_scope_and_validity(raw))
    else:  # revoke
        for field in _STATE_FIELDS:
            if field in raw:
                raise InvalidConsentEvent(f"revoke must not carry {field}")
    return event


def _validate_chain(events: list[dict]) -> list[dict]:
    """Check one consent's events and return them ordered by version."""
    by_version: dict[int, dict] = {}
    for event in events:
        if event["version"] in by_version:
            raise InvalidConsentEvent("version must be unique within a consent")
        by_version[event["version"]] = event
    versions = sorted(by_version)
    if versions != list(range(1, len(versions) + 1)):
        raise InvalidConsentEvent("versions must increase consecutively from 1")
    chain = [by_version[version] for version in versions]
    if chain[0]["type"] != "grant":
        raise InvalidConsentEvent("a consent must start with a grant")
    revoked = False
    previous_time: datetime | None = None
    for event in chain:
        if revoked:
            raise InvalidConsentEvent("no events may follow a revoke")
        if previous_time is not None and event["occurred_at"] < previous_time:
            raise InvalidConsentEvent("occurred_at must not go backwards across versions")
        previous_time = event["occurred_at"]
        if event["type"] == "revoke":
            revoked = True
    return chain


def _parse_query(raw: Any) -> dict:
    if not isinstance(raw, dict):
        raise InvalidConsentQuery("each query must be an object")
    for field in _QUERY_FIELDS:
        if field not in raw:
            raise InvalidConsentQuery(f"query is missing {field}")
    return {
        "consent_id": _require_string(raw, "consent_id", InvalidConsentQuery),
        "as_of": _parse_time(raw["as_of"], InvalidConsentQuery),
    }


def _snapshot(chain: list[dict], source: dict) -> dict:
    """The full consent state described by a grant/amend event."""
    return {
        "consent_id": source["consent_id"],
        "subject_id": chain[0]["subject_id"],
        "purposes": sorted(source["purposes"]),
        "data_categories": sorted(source["data_categories"]),
        "recipients": sorted(source["recipients"]),
        "valid_from": _format_time(source["valid_from"]),
        "valid_until": _format_time(source["valid_until"]),
    }


def _answer_query(chain: list[dict] | None, query: dict) -> dict:
    as_of = query["as_of"]
    result = {"consent_id": query["consent_id"]}
    if chain is None:
        return {**result, "status": "not_found"}
    # occurred_at is non-decreasing in version order, so the eligible events
    # (occurred_at <= as_of) always form a prefix of the chain.
    latest: dict | None = None
    for event in chain:
        if event["occurred_at"] > as_of:
            break
        latest = event
    if latest is None:
        return {**result, "status": "not_found"}
    if latest["type"] == "revoke":
        status = "revoked"
        source = next(event for event in reversed(chain) if event["version"] < latest["version"])
    else:
        source = latest
        if as_of < source["valid_from"]:
            status = "pending"
        elif as_of >= source["valid_until"]:
            status = "expired"
        else:
            status = "active"
    return {
        **result,
        "status": status,
        "version": latest["version"],
        "last_event_id": latest["event_id"],
        "snapshot": _snapshot(chain, source),
    }


def consent_timeline_request(payload: Any) -> list[dict]:
    """Validate a /v1/consent/timeline payload and rebuild every query."""
    if not isinstance(payload, dict):
        raise InvalidRequest("request body must be a JSON object")
    raw_events = payload.get("events")
    if not isinstance(raw_events, list) or not raw_events:
        raise InvalidRequest("events must be a non-empty array")
    raw_queries = payload.get("queries")
    if not isinstance(raw_queries, list) or not raw_queries:
        raise InvalidRequest("queries must be a non-empty array")

    events = [_parse_event(raw) for raw in raw_events]
    seen_event_ids: set[str] = set()
    for event in events:
        if event["event_id"] in seen_event_ids:
            raise InvalidConsentEvent("event_id must be unique within the request")
        seen_event_ids.add(event["event_id"])
    by_consent: dict[str, list[dict]] = {}
    for event in events:
        by_consent.setdefault(event["consent_id"], []).append(event)
    chains = {consent_id: _validate_chain(group) for consent_id, group in by_consent.items()}
    queries = [_parse_query(raw) for raw in raw_queries]

    return [_answer_query(chains.get(query["consent_id"]), query) for query in queries]
