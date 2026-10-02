"""Request-scoped consent and purpose-constraint evaluation.

Pure and request-scoped like the other capabilities: consents and accesses
are validated up front (no partial results), the payload is only read, and
nothing is retained between requests. An access is allowed only when a
single active consent covers its subject, purpose, data category and
recipient and the request time falls inside the consent's validity window.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any

from .classifier import CATEGORIES, InvalidRequest

STATUSES: tuple[str, ...] = ("active", "revoked")

_CATEGORY_SET = frozenset(CATEGORIES)
_STATUS_SET = frozenset(STATUSES)


class InvalidConsent(ValueError):
    """A consent entry is malformed or inconsistent."""


class InvalidAccess(ValueError):
    """An access entry is malformed."""


# RFC 3339 date-time with an explicit offset (seconds are required).
_RFC3339_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[Zz]|[+-]\d{2}:\d{2})$"
)


def _parse_time(raw: Any, error: type[ValueError]) -> datetime:
    """Parse an RFC 3339 timestamp that must carry a timezone offset."""
    if not isinstance(raw, str) or not _RFC3339_RE.fullmatch(raw):
        raise error("timestamps must be RFC 3339 date-times with a timezone offset")
    text = raw[:-1] + "+00:00" if raw[-1] in "Zz" else raw
    text = text[:10] + "T" + text[11:]
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        raise error("timestamps must be valid RFC 3339 date-times") from None


def _require_text(raw: Any, field: str, error: type[ValueError]) -> str:
    if not isinstance(raw, str) or not raw:
        raise error(f"{field} must be a non-empty string")
    return raw


def _parse_scope_set(
    raw: Any, field: str, error: type[ValueError], allowed: frozenset[str] | None = None
) -> frozenset[str]:
    """Validate a non-empty, duplicate-free scope set of strings."""
    if not isinstance(raw, list) or not raw:
        raise error(f"{field} must be a non-empty array")
    seen: set[str] = set()
    for item in raw:
        if not isinstance(item, str) or not item:
            raise error(f"{field} entries must be non-empty strings")
        if allowed is not None and item not in allowed:
            raise error(f"{field} contains an unsupported category")
        if item in seen:
            raise error(f"{field} must not contain duplicates")
        seen.add(item)
    return frozenset(seen)


class _Consent:
    __slots__ = (
        "consent_id",
        "subject_id",
        "purposes",
        "data_categories",
        "recipients",
        "valid_from",
        "valid_until",
        "status",
    )

    def __init__(self, raw: dict) -> None:
        for field in (
            "consent_id",
            "subject_id",
            "purposes",
            "data_categories",
            "recipients",
            "valid_from",
            "valid_until",
            "status",
        ):
            if field not in raw:
                raise InvalidConsent(f"consent is missing required field {field!r}")
        self.consent_id = _require_text(raw["consent_id"], "consent_id", InvalidConsent)
        self.subject_id = _require_text(raw["subject_id"], "subject_id", InvalidConsent)
        self.purposes = _parse_scope_set(raw["purposes"], "purposes", InvalidConsent)
        self.data_categories = _parse_scope_set(
            raw["data_categories"], "data_categories", InvalidConsent, _CATEGORY_SET
        )
        self.recipients = _parse_scope_set(raw["recipients"], "recipients", InvalidConsent)
        status = raw["status"]
        if status not in _STATUS_SET:
            raise InvalidConsent("status must be 'active' or 'revoked'")
        self.status = status
        self.valid_from = _parse_time(raw["valid_from"], InvalidConsent)
        self.valid_until = _parse_time(raw["valid_until"], InvalidConsent)
        if self.valid_until <= self.valid_from:
            raise InvalidConsent("valid_until must be later than valid_from")


class _Access:
    __slots__ = ("subject_id", "purpose", "data_category", "recipient", "requested_at")

    def __init__(self, raw: dict) -> None:
        for field in ("subject_id", "purpose", "data_category", "recipient", "requested_at"):
            if field not in raw:
                raise InvalidAccess(f"access is missing required field {field!r}")
        self.subject_id = _require_text(raw["subject_id"], "subject_id", InvalidAccess)
        self.purpose = _require_text(raw["purpose"], "purpose", InvalidAccess)
        data_category = raw["data_category"]
        if not isinstance(data_category, str) or data_category not in _CATEGORY_SET:
            raise InvalidAccess("data_category must be one of the supported categories")
        self.data_category = data_category
        self.recipient = _require_text(raw["recipient"], "recipient", InvalidAccess)
        self.requested_at = _parse_time(raw["requested_at"], InvalidAccess)


def _parse_consents(raw: list) -> list[_Consent]:
    consents: list[_Consent] = []
    seen_ids: set[str] = set()
    for item in raw:
        if not isinstance(item, dict):
            raise InvalidConsent("each consent must be an object")
        consent = _Consent(item)
        if consent.consent_id in seen_ids:
            raise InvalidConsent("consent_id must be unique within the request")
        seen_ids.add(consent.consent_id)
        consents.append(consent)
    return consents


def _parse_accesses(raw: list) -> list[_Access]:
    accesses: list[_Access] = []
    for item in raw:
        if not isinstance(item, dict):
            raise InvalidAccess("each access must be an object")
        accesses.append(_Access(item))
    return accesses


def _covers(consent: _Consent, access: _Access) -> bool:
    return (
        consent.status == "active"
        and consent.subject_id == access.subject_id
        and access.purpose in consent.purposes
        and access.data_category in consent.data_categories
        and access.recipient in consent.recipients
        and consent.valid_from <= access.requested_at < consent.valid_until
    )


def _evaluate_access(index: int, access: _Access, consents: list[_Consent]) -> dict:
    matches = [consent for consent in consents if _covers(consent, access)]
    if not matches:
        return {"index": index, "allowed": False, "reason": "no_matching_consent"}
    latest = max(consent.valid_from for consent in matches)
    consent_id = min(
        consent.consent_id for consent in matches if consent.valid_from == latest
    )
    return {
        "index": index,
        "allowed": True,
        "reason": "consent_granted",
        "consent_id": consent_id,
    }


def evaluate_consent_request(payload: Any) -> list[dict]:
    """Validate a /v1/consent/evaluate payload and evaluate every access."""
    if not isinstance(payload, dict):
        raise InvalidRequest("request body must be a JSON object")
    raw_consents = payload.get("consents")
    if not isinstance(raw_consents, list) or not raw_consents:
        raise InvalidRequest("consents must be a non-empty array")
    raw_accesses = payload.get("accesses")
    if not isinstance(raw_accesses, list) or not raw_accesses:
        raise InvalidRequest("accesses must be a non-empty array")
    consents = _parse_consents(raw_consents)
    accesses = _parse_accesses(raw_accesses)
    return [
        _evaluate_access(index, access, consents) for index, access in enumerate(accesses)
    ]
