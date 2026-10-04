"""Stateless data-subject request processing (export / correct / delete).

Pure and request-scoped like the other modules: records and subject
requests are read from the current payload only, requests are applied in
input order to deep copies of the records, the caller's data is never
mutated, and nothing is persisted between requests. Identical inputs
always produce identical results.
"""

from __future__ import annotations

import copy
from typing import Any

from .classifier import InvalidRequest

REQUEST_TYPES: tuple[str, ...] = ("export", "correct", "delete")

_TYPE_SET = frozenset(REQUEST_TYPES)

_RECORD_FIELDS = ("record_id", "subject_id", "data")
_REQUEST_FIELDS = ("request_id", "subject_id", "type", "verified")
_CHANGE_FIELDS = ("record_id", "path", "value")


class InvalidRecord(ValueError):
    """A record entry is malformed."""


class InvalidSubjectRequest(ValueError):
    """A subject request entry is malformed."""


class InvalidCorrection(ValueError):
    """A correction entry, pointer, path set, or target is malformed."""


def _require_string(entry: dict, field: str, error: type[ValueError]) -> str:
    value = entry.get(field)
    if not isinstance(value, str) or not value:
        raise error(f"{field} must be a non-empty string")
    return value


def _parse_record(raw: Any) -> dict:
    if not isinstance(raw, dict):
        raise InvalidRecord("each record must be an object")
    for field in _RECORD_FIELDS:
        if field not in raw:
            raise InvalidRecord(f"record is missing {field}")
    record_id = _require_string(raw, "record_id", InvalidRecord)
    subject_id = _require_string(raw, "subject_id", InvalidRecord)
    if not isinstance(raw["data"], dict):
        raise InvalidRecord("data must be an object")
    return {"record_id": record_id, "subject_id": subject_id, "data": raw["data"]}


def _parse_request(raw: Any) -> dict:
    if not isinstance(raw, dict):
        raise InvalidSubjectRequest("each request must be an object")
    for field in _REQUEST_FIELDS:
        if field not in raw:
            raise InvalidSubjectRequest(f"request is missing {field}")
    request_id = _require_string(raw, "request_id", InvalidSubjectRequest)
    subject_id = _require_string(raw, "subject_id", InvalidSubjectRequest)
    request_type = raw["type"]
    if not isinstance(request_type, str) or request_type not in _TYPE_SET:
        raise InvalidSubjectRequest("type must be 'export', 'correct', or 'delete'")
    if not isinstance(raw["verified"], bool):
        raise InvalidSubjectRequest("verified must be a boolean")
    has_changes = "changes" in raw
    if request_type == "correct":
        if not has_changes:
            raise InvalidSubjectRequest("correct requests must carry changes")
        changes = raw["changes"]
        if not isinstance(changes, list) or not changes:
            raise InvalidSubjectRequest("changes must be a non-empty array")
    elif has_changes:
        raise InvalidSubjectRequest("only correct requests may carry changes")
    return {
        "request_id": request_id,
        "subject_id": subject_id,
        "type": request_type,
        "verified": raw["verified"],
        "changes": raw.get("changes"),
    }


def _parse_pointer(path: Any) -> tuple[str, ...]:
    """Parse a non-root RFC 6901 JSON pointer into reference tokens."""
    if not isinstance(path, str) or not path.startswith("/"):
        raise InvalidCorrection("path must be a non-root RFC 6901 JSON pointer")
    tokens: list[str] = []
    for raw_token in path.split("/")[1:]:
        chars: list[str] = []
        index = 0
        while index < len(raw_token):
            char = raw_token[index]
            if char == "~":
                if index + 1 >= len(raw_token) or raw_token[index + 1] not in "01":
                    raise InvalidCorrection("path contains an invalid RFC 6901 escape")
                chars.append("~" if raw_token[index + 1] == "0" else "/")
                index += 2
            else:
                chars.append(char)
                index += 1
        tokens.append("".join(chars))
    return tuple(tokens)


def _array_index(token: str) -> int:
    if not token.isdigit() or (len(token) > 1 and token.startswith("0")):
        raise InvalidCorrection("array indices must be non-negative integers without leading zeros")
    return int(token)


def _resolve(data: Any, tokens: tuple[str, ...]) -> tuple[Any, str]:
    """Walk to the parent of the final token, which must already exist."""
    node = data
    for token in tokens[:-1]:
        if isinstance(node, dict):
            if token not in node:
                raise InvalidCorrection("path must point to an existing member")
            node = node[token]
        elif isinstance(node, list):
            index = _array_index(token)
            if index >= len(node):
                raise InvalidCorrection("path must point to an existing element")
            node = node[index]
        else:
            raise InvalidCorrection("path must traverse objects and arrays")
    last = tokens[-1]
    if isinstance(node, dict):
        if last not in node:
            raise InvalidCorrection("path must point to an existing member")
    elif isinstance(node, list):
        if _array_index(last) >= len(node):
            raise InvalidCorrection("path must point to an existing element")
    else:
        raise InvalidCorrection("path must point to an existing member or element")
    return node, last


def _parse_change(raw: Any) -> dict:
    if not isinstance(raw, dict):
        raise InvalidCorrection("each change must be an object")
    for field in _CHANGE_FIELDS:
        if field not in raw:
            raise InvalidCorrection(f"change is missing {field}")
    record_id = _require_string(raw, "record_id", InvalidCorrection)
    tokens = _parse_pointer(raw.get("path"))
    return {
        "record_id": record_id,
        "path": raw["path"],
        "tokens": tokens,
        "value": raw["value"],
    }


def _check_path_overlap(changes: list[dict]) -> None:
    """Within one record, paths must not duplicate or nest inside each other."""
    by_record: dict[str, list[tuple[str, ...]]] = {}
    for change in changes:
        by_record.setdefault(change["record_id"], []).append(change["tokens"])
    for tokens_list in by_record.values():
        for left_index in range(len(tokens_list)):
            left = tokens_list[left_index]
            for right in tokens_list[left_index + 1 :]:
                shared = len(left) if len(left) <= len(right) else len(right)
                if left[:shared] == right[:shared]:
                    raise InvalidCorrection("paths within one record must not duplicate or nest")


def _apply_correct(request: dict, by_id: dict[str, dict]) -> list[dict]:
    """Validate every change, then apply them atomically against live records."""
    changes = [_parse_change(raw) for raw in request["changes"]]
    _check_path_overlap(changes)
    resolved: list[tuple[Any, str, Any]] = []
    for change in changes:
        record = by_id.get(change["record_id"])
        if record is None:
            raise InvalidCorrection("change target record does not exist")
        if record["subject_id"] != request["subject_id"]:
            raise InvalidCorrection("change target record belongs to another subject")
        parent, token = _resolve(record["data"], change["tokens"])
        resolved.append((parent, token, change["value"]))
    for parent, token, value in resolved:
        if isinstance(parent, dict):
            parent[token] = copy.deepcopy(value)
        else:
            parent[_array_index(token)] = copy.deepcopy(value)
    locations = [{"record_id": c["record_id"], "path": c["path"]} for c in changes]
    locations.sort(key=lambda item: (item["record_id"], item["path"]))
    return locations


def _apply_request(request: dict, records: list[dict], by_id: dict[str, dict]) -> dict:
    result = {"request_id": request["request_id"]}
    if not request["verified"]:
        return {**result, "status": "rejected", "reason": "identity_not_verified"}
    request_type = request["type"]
    if request_type == "export":
        matched = sorted(
            (r for r in records if r["subject_id"] == request["subject_id"]),
            key=lambda r: r["record_id"],
        )
        return {
            **result,
            "status": "exported",
            "records": [
                {"record_id": r["record_id"], "data": copy.deepcopy(r["data"])} for r in matched
            ],
        }
    if request_type == "delete":
        deleted_ids = sorted(r["record_id"] for r in records if r["subject_id"] == request["subject_id"])
        if deleted_ids:
            removed = frozenset(deleted_ids)
            records[:] = [r for r in records if r["record_id"] not in removed]
            for record_id in deleted_ids:
                del by_id[record_id]
        return {
            **result,
            "status": "deleted",
            "deleted_count": len(deleted_ids),
            "record_ids": deleted_ids,
        }
    locations = _apply_correct(request, by_id)
    return {**result, "status": "corrected", "changes": locations}


def process_subject_requests(payload: Any) -> dict:
    """Validate a /v1/subject-requests/process payload and apply every request."""
    if not isinstance(payload, dict):
        raise InvalidRequest("request body must be a JSON object")
    raw_records = payload.get("records")
    if not isinstance(raw_records, list) or not raw_records:
        raise InvalidRequest("records must be a non-empty array")
    raw_requests = payload.get("requests")
    if not isinstance(raw_requests, list) or not raw_requests:
        raise InvalidRequest("requests must be a non-empty array")

    records = [_parse_record(raw) for raw in raw_records]
    seen_record_ids: set[str] = set()
    for record in records:
        if record["record_id"] in seen_record_ids:
            raise InvalidRecord("record_id must be unique within the request")
        seen_record_ids.add(record["record_id"])
    requests = [_parse_request(raw) for raw in raw_requests]
    seen_request_ids: set[str] = set()
    for request in requests:
        if request["request_id"] in seen_request_ids:
            raise InvalidSubjectRequest("request_id must be unique within the request")
        seen_request_ids.add(request["request_id"])

    working = [
        {"record_id": r["record_id"], "subject_id": r["subject_id"], "data": copy.deepcopy(r["data"])}
        for r in records
    ]
    by_id = {r["record_id"]: r for r in working}

    results = [_apply_request(request, working, by_id) for request in requests]
    final_records = [
        {"record_id": r["record_id"], "subject_id": r["subject_id"], "data": r["data"]}
        for r in working
    ]
    return {"results": results, "records": final_records}
