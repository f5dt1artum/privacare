"""Request-level cross-border transfer compliance evaluation.

Pure and request-scoped like the other modules: rules and transfers are
read from the current payload only, nothing is persisted between requests,
the caller's data is never mutated, and identical inputs always produce
identical results. Each transfer is judged against the rules
of the same request; rules are never combined, and a transfer with no
matching rule is denied by default.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any

from .classifier import CATEGORIES, InvalidRequest

EFFECTS: tuple[str, ...] = ("allow", "deny")

_CATEGORY_SET = frozenset(CATEGORIES)
_EFFECT_SET = frozenset(EFFECTS)

_MIN_PRIORITY = 0
_MAX_PRIORITY = 1000

_RULE_FIELDS = (
    "rule_id",
    "priority",
    "effect",
    "source_jurisdictions",
    "destination_jurisdictions",
    "purposes",
    "legal_bases",
    "data_categories",
    "valid_from",
    "valid_until",
)

_TRANSFER_FIELDS = (
    "transfer_id",
    "source_jurisdiction",
    "destination_jurisdiction",
    "purpose",
    "legal_basis",
    "data_categories",
    "requested_at",
)

# RFC 3339 date-time with a mandatory numeric offset or "Z".
_RFC3339_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$"
)


class InvalidRule(ValueError):
    """A rule entry is malformed."""


class InvalidTransfer(ValueError):
    """A transfer entry is malformed."""


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


def _parse_rule(raw: Any) -> dict:
    if not isinstance(raw, dict):
        raise InvalidRule("each rule must be an object")
    for field in _RULE_FIELDS:
        if field not in raw:
            raise InvalidRule(f"rule is missing {field}")
    rule_id = _require_string(raw, "rule_id", InvalidRule)
    priority = raw["priority"]
    if not isinstance(priority, int) or isinstance(priority, bool):
        raise InvalidRule("priority must be an integer")
    if not _MIN_PRIORITY <= priority <= _MAX_PRIORITY:
        raise InvalidRule("priority must be between 0 and 1000")
    effect = raw["effect"]
    if not isinstance(effect, str) or effect not in _EFFECT_SET:
        raise InvalidRule("effect must be 'allow' or 'deny'")
    source_jurisdictions = _require_string_set(raw, "source_jurisdictions", InvalidRule)
    destination_jurisdictions = _require_string_set(raw, "destination_jurisdictions", InvalidRule)
    purposes = _require_string_set(raw, "purposes", InvalidRule)
    legal_bases = _require_string_set(raw, "legal_bases", InvalidRule)
    data_categories = _require_string_set(raw, "data_categories", InvalidRule)
    if not data_categories <= _CATEGORY_SET:
        raise InvalidRule("data_categories contains an unsupported category")
    valid_from = _parse_time(raw["valid_from"], InvalidRule)
    valid_until = _parse_time(raw["valid_until"], InvalidRule)
    if valid_until <= valid_from:
        raise InvalidRule("valid_until must be later than valid_from")
    return {
        "rule_id": rule_id,
        "priority": priority,
        "effect": effect,
        "source_jurisdictions": source_jurisdictions,
        "destination_jurisdictions": destination_jurisdictions,
        "purposes": purposes,
        "legal_bases": legal_bases,
        "data_categories": data_categories,
        "valid_from": valid_from,
        "valid_until": valid_until,
    }


def _parse_transfer(raw: Any) -> dict:
    if not isinstance(raw, dict):
        raise InvalidTransfer("each transfer must be an object")
    for field in _TRANSFER_FIELDS:
        if field not in raw:
            raise InvalidTransfer(f"transfer is missing {field}")
    transfer_id = _require_string(raw, "transfer_id", InvalidTransfer)
    source_jurisdiction = _require_string(raw, "source_jurisdiction", InvalidTransfer)
    destination_jurisdiction = _require_string(raw, "destination_jurisdiction", InvalidTransfer)
    if source_jurisdiction == destination_jurisdiction:
        raise InvalidTransfer("source_jurisdiction and destination_jurisdiction must differ")
    purpose = _require_string(raw, "purpose", InvalidTransfer)
    legal_basis = _require_string(raw, "legal_basis", InvalidTransfer)
    data_categories = _require_string_set(raw, "data_categories", InvalidTransfer)
    if not data_categories <= _CATEGORY_SET:
        raise InvalidTransfer("data_categories contains an unsupported category")
    requested_at = _parse_time(raw["requested_at"], InvalidTransfer)
    return {
        "transfer_id": transfer_id,
        "source_jurisdiction": source_jurisdiction,
        "destination_jurisdiction": destination_jurisdiction,
        "purpose": purpose,
        "legal_basis": legal_basis,
        "data_categories": data_categories,
        "requested_at": requested_at,
    }


def _matches(rule: dict, transfer: dict) -> bool:
    """Whether one rule alone applies to one transfer."""
    return (
        transfer["source_jurisdiction"] in rule["source_jurisdictions"]
        and transfer["destination_jurisdiction"] in rule["destination_jurisdictions"]
        and transfer["purpose"] in rule["purposes"]
        and transfer["legal_basis"] in rule["legal_bases"]
        and transfer["data_categories"] <= rule["data_categories"]
        and rule["valid_from"] <= transfer["requested_at"] < rule["valid_until"]
    )


def _select(rules: list[dict], transfer: dict) -> dict | None:
    """Pick the matching rule with the highest priority, preferring deny on
    ties and then the lexicographically smallest rule_id. Rules are never
    combined: a single rule must match the whole transfer."""
    best: dict | None = None
    for rule in rules:
        if not _matches(rule, transfer):
            continue
        if best is None:
            best = rule
            continue
        if rule["priority"] != best["priority"]:
            if rule["priority"] > best["priority"]:
                best = rule
        elif rule["effect"] != best["effect"]:
            if rule["effect"] == "deny":
                best = rule
        elif rule["rule_id"] < best["rule_id"]:
            best = rule
    return best


def transfer_evaluate_request(payload: Any) -> list[dict]:
    """Validate a /v1/compliance/transfer/evaluate payload and rule on every transfer."""
    if not isinstance(payload, dict):
        raise InvalidRequest("request body must be a JSON object")
    raw_rules = payload.get("rules")
    if not isinstance(raw_rules, list) or not raw_rules:
        raise InvalidRequest("rules must be a non-empty array")
    raw_transfers = payload.get("transfers")
    if not isinstance(raw_transfers, list) or not raw_transfers:
        raise InvalidRequest("transfers must be a non-empty array")

    rules = [_parse_rule(raw) for raw in raw_rules]
    seen_rule_ids: set[str] = set()
    for rule in rules:
        if rule["rule_id"] in seen_rule_ids:
            raise InvalidRule("rule_id must be unique within the request")
        seen_rule_ids.add(rule["rule_id"])
    transfers = [_parse_transfer(raw) for raw in raw_transfers]
    seen_transfer_ids: set[str] = set()
    for transfer in transfers:
        if transfer["transfer_id"] in seen_transfer_ids:
            raise InvalidTransfer("transfer_id must be unique within the request")
        seen_transfer_ids.add(transfer["transfer_id"])

    results: list[dict] = []
    for index, transfer in enumerate(transfers):
        rule = _select(rules, transfer)
        if rule is None:
            results.append(
                {
                    "index": index,
                    "transfer_id": transfer["transfer_id"],
                    "allowed": False,
                    "reason": "no_matching_rule",
                }
            )
        elif rule["effect"] == "allow":
            results.append(
                {
                    "index": index,
                    "transfer_id": transfer["transfer_id"],
                    "allowed": True,
                    "reason": "transfer_allowed",
                    "rule_id": rule["rule_id"],
                }
            )
        else:
            results.append(
                {
                    "index": index,
                    "transfer_id": transfer["transfer_id"],
                    "allowed": False,
                    "reason": "transfer_denied",
                    "rule_id": rule["rule_id"],
                }
            )
    return results
