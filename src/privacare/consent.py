"""Request-level consent and purpose-constraint evaluation.

Pure and request-scoped like the other modules: consents and accesses are
read from the current payload only, nothing is persisted between requests,
the caller's data is never mutated, and identical inputs always produce
identical results.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any

from .classifier import CATEGORIES, InvalidRequest

STATUSES: tuple[str, ...] = ("active", "revoked")

_CATEGORY_SET = frozenset(CATEGORIES)
_STATUS_SET = frozenset(STATUSES)

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
