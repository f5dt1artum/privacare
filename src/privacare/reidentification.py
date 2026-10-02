"""k-anonymity re-identification risk evaluation for medical records.

All logic here is pure and request-scoped: equivalence classes and risk
figures are derived solely from the current request payload, caller data is
never mutated, and nothing leaks across requests.
"""

from __future__ import annotations

from decimal import ROUND_HALF_UP, Decimal
from typing import Any

from .classifier import InvalidSchema, _parse_pointer, _validate_records


class InvalidQuasiIdentifiers(ValueError):
    """The caller-supplied quasi-identifier pointers are malformed or do
    not resolve to a JSON scalar in every record."""


class InvalidK(ValueError):
    """The caller-supplied k is not a JSON integer >= 2."""


_MISSING = object()

_QUANTUM = Decimal("0.000001")


def _parse_quasi_identifiers(raw: Any) -> list[tuple[str, ...]]:
    """Validate the quasi_identifiers array into parsed pointer segments."""
    if not isinstance(raw, list) or not raw:
        raise InvalidQuasiIdentifiers("quasi_identifiers must be a non-empty array")
    seen: set[str] = set()
    pointers: list[tuple[str, ...]] = []
    for item in raw:
        if not isinstance(item, str):
            raise InvalidQuasiIdentifiers("quasi_identifiers must be JSON pointer strings")
        if item in seen:
            raise InvalidQuasiIdentifiers("quasi_identifiers must not contain duplicates")
        seen.add(item)
        try:
            pointers.append(_parse_pointer(item))
        except InvalidSchema as exc:
            raise InvalidQuasiIdentifiers(str(exc)) from exc
    return pointers


def _parse_k(raw: Any) -> int:
    """Validate k: a JSON integer (never a bool) that is at least 2."""
    if isinstance(raw, bool) or not isinstance(raw, int):
        raise InvalidK("k must be a JSON integer")
    if raw < 2:
        raise InvalidK("k must be at least 2")
    return raw


def _resolve(record: dict, segments: tuple[str, ...]) -> Any:
    node: Any = record
    for segment in segments:
        if isinstance(node, dict):
            if segment not in node:
                return _MISSING
            node = node[segment]
        elif isinstance(node, list):
            if not segment.isascii() or not segment.isdigit():
                return _MISSING
            index = int(segment)
            if index >= len(node):
                return _MISSING
            node = node[index]
        else:
            return _MISSING
    return node


def _scalar_key(value: Any) -> tuple:
    """Hashable grouping key for a JSON scalar.

    Strings compare case-sensitively, booleans never equal numbers, and
    JSON numbers compare by numeric value (1 equals 1.0).
    """
    if value is None:
        return ("null",)
    if isinstance(value, bool):
        return ("bool", value)
    if isinstance(value, (int, float)):
        return ("number", Decimal(value))
    return ("string", value)


def _record_key(record: dict, pointers: list[tuple[str, ...]]) -> tuple:
    parts = []
    for segments in pointers:
        node = _resolve(record, segments)
        if node is _MISSING or isinstance(node, (dict, list)):
            raise InvalidQuasiIdentifiers(
                "each quasi-identifier must resolve to a JSON scalar in every record"
            )
        parts.append(_scalar_key(node))
    return tuple(parts)


def _rounded(numerator: int, denominator: int) -> float:
    """numerator / denominator rounded half-up to six decimal places."""
    value = Decimal(numerator) / Decimal(denominator)
    return float(value.quantize(_QUANTUM, rounding=ROUND_HALF_UP))


def reidentification_risk_request(payload: Any) -> dict:
    """Validate a /v1/reidentification-risk payload and evaluate k-anonymity."""
    records = _validate_records(payload)
    pointers = _parse_quasi_identifiers(payload.get("quasi_identifiers"))
    keys = [_record_key(record, pointers) for record in records]
    k = _parse_k(payload.get("k"))

    sizes: dict[tuple, int] = {}
    for key in keys:
        sizes[key] = sizes.get(key, 0) + 1

    record_count = len(records)
    at_risk_records = sum(1 for key in keys if sizes[key] < k)
    results = [
        {
            "index": index,
            "class_size": sizes[key],
            "risk_score": _rounded(1, sizes[key]),
            "at_risk": sizes[key] < k,
        }
        for index, key in enumerate(keys)
    ]
    summary = {
        "k": k,
        "record_count": record_count,
        "equivalence_class_count": len(sizes),
        "minimum_class_size": min(sizes.values()),
        "at_risk_records": at_risk_records,
        "at_risk_rate": _rounded(at_risk_records, record_count),
    }
    return {"summary": summary, "results": results}
