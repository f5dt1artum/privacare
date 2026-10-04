"""Stateless data-subject request processing (export, correct, delete).

Pure and request-scoped like the other modules: records and requests are
read from the current payload only, nothing is persisted between
requests, the caller's data is never mutated, and identical inputs
always produce identical results. The subject requests are applied in
input order to a private deep copy of the records; a correction is
validated as a whole before any of its changes lands, so a failed
request raises before any output is produced and never returns partial
results.
"""

from __future__ import annotations

import copy
from typing import Any

from .classifier import InvalidRequest

_REQUEST_TYPES: tuple[str, ...] = ("export", "correct", "delete")

_RECORD_FIELDS = frozenset({"record_id", "subject_id", "data"})
_CHANGE_FIELDS = frozenset({"record_id", "path", "value"})


class InvalidRecord(ValueError):
    """A record entry is malformed or its record_id is duplicated."""


class InvalidSubjectRequest(ValueError):
    """A subject request entry is malformed."""


class InvalidCorrection(ValueError):
    """A correct request's change set cannot be applied to the current state."""


_MISSING = object()


def _require_non_empty_string(value: Any, what: str, error: type[ValueError]) -> str:
    if not isinstance(value, str) or not value:
        raise error(f"{what} must be a non-empty string")
    return value


def _parse_record(raw: Any) -> dict:
    if not isinstance(raw, dict):
        raise InvalidRecord("each record must be an object")
    if set(raw) != _RECORD_FIELDS:
        raise InvalidRecord("each record must contain exactly record_id, subject_id and data")
    record_id = _require_non_empty_string(raw["record_id"], "record_id", InvalidRecord)
    subject_id = _require_non_empty_string(raw["subject_id"], "subject_id", InvalidRecord)
    if not isinstance(raw["data"], dict):
        raise InvalidRecord("record data must be an object")
    return {"record_id": record_id, "subject_id": subject_id, "data": raw["data"]}


def _parse_pointer(raw: Any) -> tuple[str, ...]:
    """Parse a non-root RFC 6901 JSON Pointer into unescaped segments."""
    if not isinstance(raw, str) or not raw.startswith("/"):
        raise InvalidCorrection("change path must be a non-root JSON Pointer string starting with '/'")
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
                    raise InvalidCorrection("invalid '~' escape in change path")
                i += 2
            else:
                out.append(ch)
                i += 1
        segments.append("".join(out))
    return tuple(segments)


def _is_ancestor(a: tuple[str, ...], b: tuple[str, ...]) -> bool:
    return len(a) < len(b) and b[: len(a)] == a


def _parse_request(raw: Any) -> dict:
    if not isinstance(raw, dict):
        raise InvalidSubjectRequest("each request must be an object")
    for field in ("request_id", "subject_id", "type", "verified"):
        if field not in raw:
            raise InvalidSubjectRequest(f"request is missing {field}")
    request_id = _require_non_empty_string(
        raw["request_id"], "request_id", InvalidSubjectRequest
    )
    subject_id = _require_non_empty_string(
        raw["subject_id"], "subject_id", InvalidSubjectRequest
    )
    request_type = raw["type"]
    if not isinstance(request_type, str) or request_type not in _REQUEST_TYPES:
        raise InvalidSubjectRequest("type must be 'export', 'correct' or 'delete'")
    verified = raw["verified"]
    if not isinstance(verified, bool):
        raise InvalidSubjectRequest("verified must be a boolean")
    has_changes = "changes" in raw
    if request_type == "correct":
        if not has_changes:
            raise InvalidSubjectRequest("correct requests must carry changes")
    elif has_changes:
        raise InvalidSubjectRequest(f"{request_type} requests must not carry changes")
    changes: list[dict] | None = None
    if request_type == "correct":
        raw_changes = raw["changes"]
        if not isinstance(raw_changes, list) or not raw_changes:
            raise InvalidCorrection("changes must be a non-empty array")
        changes = []
        for entry in raw_changes:
            if not isinstance(entry, dict) or set(entry) != _CHANGE_FIELDS:
                raise InvalidCorrection(
                    "each change must be an object with exactly record_id, path and value"
                )
            change_record_id = _require_non_empty_string(
                entry["record_id"], "change record_id", InvalidCorrection
            )
            segments = _parse_pointer(entry["path"])
            changes.append(
                {
                    "record_id": change_record_id,
                    "path": entry["path"],
                    "segments": segments,
                    "value": entry["value"],
                }
            )
        # Path overlap is a static property of the request: reject it even
        # when identity verification would otherwise stop processing.
        per_record: dict[str, list[tuple[str, ...]]] = {}
        for item in changes:
            per_record.setdefault(item["record_id"], []).append(item["segments"])
        for paths in per_record.values():
            ordered = sorted(paths)
            for i, path in enumerate(ordered):
                for other in ordered[i + 1 :]:
                    if path == other or _is_ancestor(path, other):
                        raise InvalidCorrection(
                            "change paths must not repeat or be ancestors of each other"
                        )
    return {
        "request_id": request_id,
        "subject_id": subject_id,
        "type": request_type,
        "verified": verified,
        "changes": changes,
    }


def _resolve(node: Any, segments: tuple[str, ...]) -> Any:
    """Resolve a JSON Pointer; return _MISSING when it does not resolve."""
    for segment in segments:
        if isinstance(node, dict):
            if segment not in node:
                return _MISSING
            node = node[segment]
        elif isinstance(node, list):
            # RFC 6901: "-" never resolves, only "0" may start with '0'.
            if segment == "-" or not segment.isdigit():
                return _MISSING
            if segment != "0" and segment[0] == "0":
                return _MISSING
            index = int(segment)
            if index >= len(node):
                return _MISSING
            node = node[index]
        else:
            return _MISSING
    return node


def _set_value(node: Any, segments: tuple[str, ...], value: Any) -> None:
    for segment in segments[:-1]:
        node = node[int(segment)] if isinstance(node, list) else node[segment]
    last = segments[-1]
    if isinstance(node, list):
        node[int(last)] = value
    else:
        node[last] = value


def _validate_changes(request: dict, records_by_id: dict[str, dict]) -> list[dict]:
    """Validate a verified correct request against the current state.

    Static shape and path-overlap checks happen during parsing; here every
    target must currently exist, belong to the request subject and resolve
    to an existing object member or array element. Returns the validated
    locations ordered by record_id then path.
    """
    changes = request["changes"]
    assert changes is not None
    for change in changes:
        record = records_by_id.get(change["record_id"])
        if record is None:
            raise InvalidCorrection("change target record must exist at request time")
        if record["subject_id"] != request["subject_id"]:
            raise InvalidCorrection("change target record must belong to the request subject")
        if _resolve(record["data"], change["segments"]) is _MISSING:
            raise InvalidCorrection(
                "change path must point to an existing member or array element"
            )
    ordered_changes = sorted(changes, key=lambda change: (change["record_id"], change["path"]))
    return [{"record_id": change["record_id"], "path": change["path"]} for change in ordered_changes]


def process_subject_requests(payload: Any) -> dict:
    """Validate and process a /v1/subject-requests/process payload."""
    if not isinstance(payload, dict):
        raise InvalidRequest("request body must be a JSON object")
    raw_records = payload.get("records")
    if not isinstance(raw_records, list) or not raw_records:
        raise InvalidRequest("records must be a non-empty array")
    raw_requests = payload.get("requests")
    if not isinstance(raw_requests, list) or not raw_requests:
        raise InvalidRequest("requests must be a non-empty array")

    # Parse on the caller's values without retaining or mutating them; the
    # working state below is a private deep copy.
    parsed_records = [_parse_record(raw) for raw in raw_records]
    records_by_id: dict[str, dict] = {}
    for record in parsed_records:
        if record["record_id"] in records_by_id:
            raise InvalidRecord("record_id must be unique within the request")
        records_by_id[record["record_id"]] = record

    parsed_requests: list[dict] = []
    seen_request_ids: set[str] = set()
    for raw in raw_requests:
        request = _parse_request(raw)
        if request["request_id"] in seen_request_ids:
            raise InvalidSubjectRequest("request_id must be unique within the request")
        seen_request_ids.add(request["request_id"])
        parsed_requests.append(request)

    working = copy.deepcopy(parsed_records)
    working_by_id = {record["record_id"]: record for record in working}
    results: list[dict] = []
    for request in parsed_requests:
        result: dict = {"request_id": request["request_id"], "type": request["type"]}
        if not request["verified"]:
            result["status"] = "rejected"
            result["reason"] = "identity_not_verified"
            results.append(result)
            continue
        if request["type"] == "export":
            # Snapshot the subject's records at this point in the sequence;
            # later corrections must not rewrite an earlier export result.
            entries = [
                {"record_id": record["record_id"], "data": copy.deepcopy(record["data"])}
                for record in working
                if record["subject_id"] == request["subject_id"]
            ]
            entries.sort(key=lambda entry: entry["record_id"])
            result["status"] = "completed"
            result["records"] = entries
        elif request["type"] == "delete":
            removed = [
                record for record in working if record["subject_id"] == request["subject_id"]
            ]
            removed.sort(key=lambda record: record["record_id"])
            for record in removed:
                working.remove(record)
                del working_by_id[record["record_id"]]
            result["status"] = "completed"
            result["deleted_count"] = len(removed)
            result["record_ids"] = [record["record_id"] for record in removed]
        else:
            # Validate the whole change set before applying any of it.
            locations = _validate_changes(request, working_by_id)
            for change in request["changes"]:
                target_record = working_by_id[change["record_id"]]
                _set_value(
                    target_record["data"], change["segments"], copy.deepcopy(change["value"])
                )
            result["status"] = "completed"
            result["changes"] = locations
        results.append(result)

    final_records = [
        {
            "record_id": record["record_id"],
            "subject_id": record["subject_id"],
            "data": record["data"],
        }
        for record in working
    ]
    return {"results": results, "records": final_records}
