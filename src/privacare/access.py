"""Request-level minimal-necessary access authorization.

Pure and request-scoped like the other modules: grants and accesses are
read from the current payload only, nothing is persisted between requests,
the caller's data is never mutated, and identical inputs always produce
identical results. This module judges whether a principal may perform an
operation on specific categories and fields of a resource; it does not
replace consent evaluation.
"""

from __future__ import annotations

from typing import Any

from .classifier import CATEGORIES, InvalidRequest

OPERATIONS: tuple[str, ...] = ("read", "update", "export", "delete")

_CATEGORY_SET = frozenset(CATEGORIES)
_OPERATION_SET = frozenset(OPERATIONS)

_GRANT_FIELDS = (
    "grant_id",
    "principal_id",
    "resource",
    "purpose",
    "operations",
    "data_categories",
    "field_scopes",
)

_ACCESS_FIELDS = (
    "principal_id",
    "resource",
    "purpose",
    "operation",
    "data_categories",
    "fields",
)


class InvalidGrant(ValueError):
    """A grant entry is malformed."""


class InvalidAccess(ValueError):
    """An access entry is malformed."""


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


def _parse_pointer(raw: Any, error: type[ValueError]) -> tuple[str, ...]:
    """Validate an RFC 6901 JSON Pointer and return its unescaped segments."""
    if not isinstance(raw, str):
        raise error("pointers must be JSON Pointer strings")
    if raw != "" and not raw.startswith("/"):
        raise error("pointers must be valid RFC 6901 JSON Pointers")
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
                    raise error("invalid '~' escape in JSON Pointer")
                i += 2
            else:
                out.append(ch)
                i += 1
        segments.append("".join(out))
    return tuple(segments)


def _require_pointer_set(entry: dict, field: str, error: type[ValueError]) -> frozenset[tuple[str, ...]]:
    value = entry.get(field)
    if not isinstance(value, list) or not value:
        raise error(f"{field} must be a non-empty array")
    seen: set[str] = set()
    pointers: list[tuple[str, ...]] = []
    for item in value:
        segments = _parse_pointer(item, error)
        if item in seen:
            raise error(f"{field} must not contain duplicates")
        seen.add(item)
        pointers.append(segments)
    return frozenset(pointers)


def _parse_grant(raw: Any) -> dict:
    if not isinstance(raw, dict):
        raise InvalidGrant("each grant must be an object")
    for field in _GRANT_FIELDS:
        if field not in raw:
            raise InvalidGrant(f"grant is missing {field}")
    grant_id = _require_string(raw, "grant_id", InvalidGrant)
    principal_id = _require_string(raw, "principal_id", InvalidGrant)
    resource = _require_string(raw, "resource", InvalidGrant)
    purpose = _require_string(raw, "purpose", InvalidGrant)
    operations = _require_string_set(raw, "operations", InvalidGrant)
    if not operations <= _OPERATION_SET:
        raise InvalidGrant("operations contains an unsupported operation")
    data_categories = _require_string_set(raw, "data_categories", InvalidGrant)
    if not data_categories <= _CATEGORY_SET:
        raise InvalidGrant("data_categories contains an unsupported category")
    field_scopes = _require_pointer_set(raw, "field_scopes", InvalidGrant)
    return {
        "grant_id": grant_id,
        "principal_id": principal_id,
        "resource": resource,
        "purpose": purpose,
        "operations": operations,
        "data_categories": data_categories,
        "field_scopes": field_scopes,
    }


def _parse_access(raw: Any) -> dict:
    if not isinstance(raw, dict):
        raise InvalidAccess("each access must be an object")
    for field in _ACCESS_FIELDS:
        if field not in raw:
            raise InvalidAccess(f"access is missing {field}")
    principal_id = _require_string(raw, "principal_id", InvalidAccess)
    resource = _require_string(raw, "resource", InvalidAccess)
    purpose = _require_string(raw, "purpose", InvalidAccess)
    operation = raw["operation"]
    if not isinstance(operation, str) or operation not in _OPERATION_SET:
        raise InvalidAccess("operation is not a supported operation")
    data_categories = _require_string_set(raw, "data_categories", InvalidAccess)
    if not data_categories <= _CATEGORY_SET:
        raise InvalidAccess("data_categories contains an unsupported category")
    fields = _require_pointer_set(raw, "fields", InvalidAccess)
    return {
        "principal_id": principal_id,
        "resource": resource,
        "purpose": purpose,
        "operation": operation,
        "data_categories": data_categories,
        "fields": fields,
    }


def _field_covered(scopes: frozenset[tuple[str, ...]], field: tuple[str, ...]) -> bool:
    """A field is covered when it equals a scope or is a descendant of one,
    where descent is judged by pointer segments."""
    return any(field[: len(scope)] == scope for scope in scopes)


def _covers(grant: dict, access: dict) -> bool:
    """Whether one grant alone fully covers one access."""
    return (
        grant["principal_id"] == access["principal_id"]
        and grant["resource"] == access["resource"]
        and grant["purpose"] == access["purpose"]
        and access["operation"] in grant["operations"]
        and access["data_categories"] <= grant["data_categories"]
        and all(_field_covered(grant["field_scopes"], field) for field in access["fields"])
    )


def _select(grants: list[dict], access: dict) -> dict | None:
    """Pick the covering grant with the lexicographically smallest grant_id.
    Grants are never combined: a single grant must cover the whole access."""
    best: dict | None = None
    for grant in grants:
        if not _covers(grant, access):
            continue
        if best is None or grant["grant_id"] < best["grant_id"]:
            best = grant
    return best


def access_evaluate_request(payload: Any) -> list[dict]:
    """Validate a /v1/access/evaluate payload and rule on every access."""
    if not isinstance(payload, dict):
        raise InvalidRequest("request body must be a JSON object")
    raw_grants = payload.get("grants")
    if not isinstance(raw_grants, list) or not raw_grants:
        raise InvalidRequest("grants must be a non-empty array")
    raw_accesses = payload.get("accesses")
    if not isinstance(raw_accesses, list) or not raw_accesses:
        raise InvalidRequest("accesses must be a non-empty array")

    grants = [_parse_grant(raw) for raw in raw_grants]
    seen_ids: set[str] = set()
    for grant in grants:
        if grant["grant_id"] in seen_ids:
            raise InvalidGrant("grant_id must be unique within the request")
        seen_ids.add(grant["grant_id"])
    accesses = [_parse_access(raw) for raw in raw_accesses]

    results: list[dict] = []
    for index, access in enumerate(accesses):
        grant = _select(grants, access)
        if grant is None:
            results.append({"index": index, "allowed": False, "reason": "no_matching_grant"})
        else:
            results.append(
                {
                    "index": index,
                    "allowed": True,
                    "reason": "access_granted",
                    "grant_id": grant["grant_id"],
                }
            )
    return results
