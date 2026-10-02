"""K-anonymity based re-identification risk measurement.

Pure and request-scoped, like the classifier and de-identifier: the
payload is only read, never mutated, and nothing is retained between
requests. Equivalence classes come from the ordered combination of the
scalar values at the caller-supplied quasi-identifier JSON Pointers.
"""

from __future__ import annotations

from decimal import Decimal, ROUND_HALF_UP
from typing import Any

from .classifier import (
    InvalidRequest,
    InvalidSchema,
    _parse_pointer,
    _validate_records,
)

_QUANTUM = Decimal("0.000001")


class InvalidQuasiIdentifiers(ValueError):
    """The quasi_identifiers array is malformed or does not resolve to scalars."""


class InvalidK(ValueError):
    """k is not a JSON integer no less than 2."""


def _round6(value: Decimal) -> float:
    """Round a decimal to six places, half up, and emit as a JSON number."""
    return float(value.quantize(_QUANTUM, rounding=ROUND_HALF_UP))


def _validate_quasi_identifiers(raw: Any) -> list[tuple[str, ...]]:
    if not isinstance(raw, list) or not raw:
        raise InvalidQuasiIdentifiers("quasi_identifiers must be a non-empty array")
    pointers: list[tuple[str, ...]] = []
    seen: set[str] = set()
    for item in raw:
        if not isinstance(item, str):
            raise InvalidQuasiIdentifiers("quasi_identifiers must be JSON Pointer strings")
        try:
            segments = _parse_pointer(item)
        except InvalidSchema as exc:
            raise InvalidQuasiIdentifiers(str(exc)) from exc
        if item in seen:
            raise InvalidQuasiIdentifiers("quasi_identifiers must not contain duplicates")
        seen.add(item)
        pointers.append(segments)
    return pointers


def _validate_k(raw: Any) -> int:
    # bool is an int subclass in Python, but JSON true/false is not a number.
    if isinstance(raw, bool) or not isinstance(raw, int) or raw < 2:
        raise InvalidK("k must be a JSON integer no less than 2")
    return raw


def _scalar_key(value: Any) -> tuple[int, Any]:
    """Build a hashable group key with JSON equality semantics.

    Tags keep the JSON types apart (true != 1, null != false) while ints
    and floats share a numeric tag keyed by their exact decimal value so
    that 1 and 1.0 land in the same equivalence class.
    """
    if value is None:
        return (0, 0)
    if isinstance(value, bool):
        return (1, value)
    if isinstance(value, int):
        return (2, Decimal(value))
    if isinstance(value, float):
        return (2, Decimal(str(value)))
    if isinstance(value, str):
        return (3, value)
    raise InvalidQuasiIdentifiers("each quasi-identifier pointer must resolve to a scalar")


def _resolve_scalar(record: dict, segments: tuple[str, ...]) -> Any:
    """Resolve a JSON Pointer, requiring the target to be a scalar.

    Array index handling follows RFC 6901: "0" alone may have a leading
    zero, every other index may not, and "-" never resolves.
    """
    node: Any = record
    for segment in segments:
        if isinstance(node, dict):
            if segment not in node:
                raise InvalidQuasiIdentifiers(
                    "every quasi-identifier pointer must resolve on every record"
                )
            node = node[segment]
        elif isinstance(node, list):
            if segment == "-" or not segment.isdigit():
                raise InvalidQuasiIdentifiers("invalid array index in quasi-identifier pointer")
            if segment != "0" and segment[0] == "0":
                raise InvalidQuasiIdentifiers("array indices must not have leading zeros")
            index = int(segment)
            if index >= len(node):
                raise InvalidQuasiIdentifiers(
                    "every quasi-identifier pointer must resolve on every record"
                )
            node = node[index]
        else:
            raise InvalidQuasiIdentifiers(
                "every quasi-identifier pointer must resolve on every record"
            )
    if isinstance(node, (dict, list)):
        raise InvalidQuasiIdentifiers("quasi-identifier pointers must resolve to scalar values")
    return node


def _row_key(record: dict, pointers: list[tuple[str, ...]]) -> tuple[tuple[int, Any], ...]:
    return tuple(_scalar_key(_resolve_scalar(record, segments)) for segments in pointers)


def reidentification_risk_request(payload: Any) -> dict:
    """Validate a /v1/reidentification-risk payload and score every record."""
    records = _validate_records(payload)
    pointers = _validate_quasi_identifiers(payload.get("quasi_identifiers"))
    k = _validate_k(payload.get("k"))

    row_keys = [_row_key(record, pointers) for record in records]
    class_sizes: dict[tuple, int] = {}
    for row_key in row_keys:
        class_sizes[row_key] = class_sizes.get(row_key, 0) + 1

    results: list[dict] = []
    at_risk_records = 0
    for index, row_key in enumerate(row_keys):
        class_size = class_sizes[row_key]
        at_risk = class_size < k
        if at_risk:
            at_risk_records += 1
        results.append(
            {
                "index": index,
                "class_size": class_size,
                "risk_score": _round6(Decimal(1) / Decimal(class_size)),
                "at_risk": at_risk,
            }
        )

    record_count = len(records)
    summary = {
        "k": k,
        "record_count": record_count,
        "equivalence_class_count": len(class_sizes),
        "minimum_class_size": min(class_sizes.values()),
        "at_risk_records": at_risk_records,
        "at_risk_rate": _round6(Decimal(at_risk_records) / Decimal(record_count)),
    }
    return {"summary": summary, "results": results}
