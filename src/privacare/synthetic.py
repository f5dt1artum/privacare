"""Stateless utility evaluation of synthetic health data.

Pure and request-scoped like the other capabilities: the real and
synthetic records are only read from the current payload, the caller's
data is never mutated and nothing is retained between requests.
Categorical fields are compared by the total variation distance of
their empirical value distributions; numeric fields use the
Kolmogorov-Smirnov distance of their empirical CDFs. Record exact
matches keep JSON type boundaries (true != 1, 1 == 1.0).
"""

from __future__ import annotations

import math
from decimal import Decimal, ROUND_HALF_UP
from typing import Any

from .classifier import InvalidRequest, InvalidSchema, _parse_pointer

_QUANTUM = Decimal("0.000001")

CATEGORICAL = "categorical"
NUMERIC = "numeric"
_KINDS = frozenset((CATEGORICAL, NUMERIC))


class InvalidRealRecords(ValueError):
    """real_records is malformed or a declared path fails to resolve on it."""


class InvalidSyntheticRecords(ValueError):
    """synthetic_records is malformed or a declared path fails on it."""


def _round6(value: Decimal) -> float:
    """Round a decimal to six places, half up, and emit as a JSON number."""
    return float(value.quantize(_QUANTUM, rounding=ROUND_HALF_UP))


def _validate_fields(raw: Any) -> list[tuple[str, tuple[str, ...], str]]:
    """Validate the fields array into (path, segments, kind) tuples."""
    fields: list[tuple[str, tuple[str, ...], str]] = []
    seen: set[str] = set()
    for item in raw:
        if not isinstance(item, dict):
            raise InvalidSchema("each field must be an object with path and kind")
        if "path" not in item or "kind" not in item:
            raise InvalidSchema("each field must contain path and kind")
        path = item["path"]
        kind = item["kind"]
        if not isinstance(path, str):
            raise InvalidSchema("field path must be a JSON Pointer string")
        segments = _parse_pointer(path)
        if not segments:
            raise InvalidSchema("field path must not be the root pointer")
        if not isinstance(kind, str) or kind not in _KINDS:
            raise InvalidSchema("field kind must be categorical or numeric")
        if path in seen:
            raise InvalidSchema("field paths must not contain duplicates")
        seen.add(path)
        fields.append((path, segments, kind))
    return fields


def _resolve_leaf(record: dict, segments: tuple[str, ...], error: type[ValueError]) -> Any:
    """Resolve a non-root JSON Pointer, requiring the target to be a leaf.

    Array index handling follows RFC 6901: "0" alone may have a leading
    zero, every other index may not, and "-" never resolves.
    """
    node: Any = record
    for segment in segments:
        if isinstance(node, dict):
            if segment not in node:
                raise error("every declared path must resolve on every record")
            node = node[segment]
        elif isinstance(node, list):
            if segment == "-" or not segment.isdigit():
                raise error("invalid array index in field path")
            if segment != "0" and segment[0] == "0":
                raise error("array indices must not have leading zeros")
            index = int(segment)
            if index >= len(node):
                raise error("every declared path must resolve on every record")
            node = node[index]
        else:
            raise error("every declared path must resolve on every record")
    if isinstance(node, (dict, list)):
        raise error("field paths must resolve to leaf values, not containers")
    return node


def _check_kind(value: Any, kind: str, error: type[ValueError]) -> None:
    if kind == CATEGORICAL:
        if value is not None and not isinstance(value, (bool, str)):
            raise error("categorical fields must be strings, booleans or null")
        return
    # bool is an int subclass in Python, but JSON true/false is not a number.
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise error("numeric fields must be finite JSON numbers")
    if isinstance(value, float) and not math.isfinite(value):
        raise error("numeric fields must be finite JSON numbers")


def _extract_rows(
    records: list[Any],
    fields: list[tuple[str, tuple[str, ...], str]],
    error: type[ValueError],
) -> list[list[Any]]:
    """Resolve and type-check every declared path on every record."""
    rows: list[list[Any]] = []
    for record in records:
        if not isinstance(record, dict):
            raise error("each record must be an object")
        row: list[Any] = []
        for _path, segments, kind in fields:
            value = _resolve_leaf(record, segments, error)
            _check_kind(value, kind, error)
            row.append(value)
        rows.append(row)
    return rows


def _categorical_distance(real_values: list[Any], synthetic_values: list[Any]) -> Decimal:
    """Total variation distance of empirical distributions over the union."""
    real_total = Decimal(len(real_values))
    synthetic_total = Decimal(len(synthetic_values))
    real_counts: dict[Any, int] = {}
    for value in real_values:
        real_counts[value] = real_counts.get(value, 0) + 1
    synthetic_counts: dict[Any, int] = {}
    for value in synthetic_values:
        synthetic_counts[value] = synthetic_counts.get(value, 0) + 1
    difference = Decimal(0)
    for value in real_counts.keys() | synthetic_counts.keys():
        real_share = Decimal(real_counts.get(value, 0)) / real_total
        synthetic_share = Decimal(synthetic_counts.get(value, 0)) / synthetic_total
        difference += abs(real_share - synthetic_share)
    return difference / 2


def _as_decimal(value: Any) -> Decimal:
    if isinstance(value, int):
        return Decimal(value)
    return Decimal(str(value))


def _numeric_distance(real_values: list[Any], synthetic_values: list[Any]) -> Decimal:
    """Kolmogorov-Smirnov distance between the two empirical CDFs."""
    real_sorted = sorted(_as_decimal(value) for value in real_values)
    synthetic_sorted = sorted(_as_decimal(value) for value in synthetic_values)
    real_total = Decimal(len(real_sorted))
    synthetic_total = Decimal(len(synthetic_sorted))

    distance = Decimal(0)
    i = j = 0
    while i < len(real_sorted) or j < len(synthetic_sorted):
        if j >= len(synthetic_sorted) or (
            i < len(real_sorted) and real_sorted[i] < synthetic_sorted[j]
        ):
            point = real_sorted[i]
        else:
            point = synthetic_sorted[j]
        # Equal numeric values (e.g. 1 and 1.0) are consumed together, so
        # the indices equal the cumulative counts <= point on both sides.
        while i < len(real_sorted) and real_sorted[i] == point:
            i += 1
        while j < len(synthetic_sorted) and synthetic_sorted[j] == point:
            j += 1
        gap = abs(Decimal(i) / real_total - Decimal(j) / synthetic_total)
        if gap > distance:
            distance = gap
    return distance


def _value_key(value: Any) -> tuple[int, Any]:
    """Tag a leaf value with JSON equality semantics for exact matching.

    Types never compare across tags (null != false != true != 1) while
    ints and floats share the numeric tag keyed by their exact decimal
    value so that 1 and 1.0 compare equal.
    """
    if value is None:
        return (0, 0)
    if isinstance(value, bool):
        return (1, value)
    if isinstance(value, int):
        return (2, Decimal(value))
    if isinstance(value, float):
        return (2, Decimal(str(value)))
    return (3, value)


def synthetic_evaluate_request(payload: Any) -> dict:
    """Validate a /v1/synthetic/evaluate payload and score utility."""
    if not isinstance(payload, dict):
        raise InvalidRequest("request body must be a JSON object")
    raw_real = payload.get("real_records")
    raw_synthetic = payload.get("synthetic_records")
    raw_fields = payload.get("fields")
    if not isinstance(raw_real, list) or not raw_real:
        raise InvalidRequest("real_records must be a non-empty array")
    if not isinstance(raw_synthetic, list) or not raw_synthetic:
        raise InvalidRequest("synthetic_records must be a non-empty array")
    if not isinstance(raw_fields, list) or not raw_fields:
        raise InvalidRequest("fields must be a non-empty array")

    fields = _validate_fields(raw_fields)
    real_rows = _extract_rows(raw_real, fields, InvalidRealRecords)
    synthetic_rows = _extract_rows(raw_synthetic, fields, InvalidSyntheticRecords)

    real_count = len(real_rows)
    synthetic_count = len(synthetic_rows)

    field_results: list[dict[str, Any]] = []
    utilities: list[Decimal] = []
    for index, (path, _segments, kind) in enumerate(fields):
        real_values = [row[index] for row in real_rows]
        synthetic_values = [row[index] for row in synthetic_rows]
        if kind == CATEGORICAL:
            distance = _categorical_distance(real_values, synthetic_values)
        else:
            distance = _numeric_distance(real_values, synthetic_values)
        utility = Decimal(1) - distance
        field_results.append(
            {
                "path": path,
                "kind": kind,
                "distance": _round6(distance),
                "utility": _round6(utility),
            }
        )
        utilities.append(utility)

    real_signatures = {
        tuple(_value_key(row[index]) for index in range(len(fields))) for row in real_rows
    }
    exact_match_count = 0
    for row in synthetic_rows:
        signature = tuple(_value_key(row[index]) for index in range(len(fields)))
        if signature in real_signatures:
            exact_match_count += 1

    field_results.sort(key=lambda field: field["path"])
    return {
        "real_count": real_count,
        "synthetic_count": synthetic_count,
        "fields": field_results,
        "overall_utility": _round6(sum(utilities, Decimal(0)) / Decimal(len(utilities))),
        "exact_match_count": exact_match_count,
        "exact_match_rate": _round6(
            Decimal(exact_match_count) / Decimal(synthetic_count)
        ),
    }
