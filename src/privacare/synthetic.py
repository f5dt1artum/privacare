"""Synthetic data utility evaluation.

Pure and request-scoped like the other capabilities: real and synthetic
records are only read from the current payload, the caller's data is never
mutated and nothing is retained between requests. Categorical fields are
scored with the total variation distance between the empirical
distributions over the union of observed values, numeric fields with the
Kolmogorov-Smirnov distance between the empirical cumulative
distributions, and each field's utility is one minus its distance.
"""

from __future__ import annotations

import math
from decimal import Decimal, ROUND_HALF_UP, localcontext
from typing import Any

from .classifier import InvalidRequest, InvalidSchema, _parse_pointer

_QUANTUM = Decimal("0.000001")

_KINDS = frozenset(("categorical", "numeric"))


class InvalidRealRecords(ValueError):
    """A real record is not an object or a declared path misses its leaf."""


class InvalidSyntheticRecords(ValueError):
    """A synthetic record is not an object or a declared path misses its leaf."""


def _round6(value: Decimal) -> float:
    """Round a decimal to six places, half up, and emit as a JSON number."""
    return float(value.quantize(_QUANTUM, rounding=ROUND_HALF_UP))


def _validate_payload(payload: Any) -> tuple[list, list, list]:
    if not isinstance(payload, dict):
        raise InvalidRequest("request body must be a JSON object")
    real_records = payload.get("real_records")
    if not isinstance(real_records, list) or not real_records:
        raise InvalidRequest("real_records must be a non-empty array")
    synthetic_records = payload.get("synthetic_records")
    if not isinstance(synthetic_records, list) or not synthetic_records:
        raise InvalidRequest("synthetic_records must be a non-empty array")
    fields = payload.get("fields")
    if not isinstance(fields, list) or not fields:
        raise InvalidRequest("fields must be a non-empty array")
    return real_records, synthetic_records, fields


def _validate_fields(raw_fields: list) -> list[tuple[str, str, tuple[str, ...]]]:
    fields: list[tuple[str, str, tuple[str, ...]]] = []
    seen: set[str] = set()
    for item in raw_fields:
        if not isinstance(item, dict):
            raise InvalidSchema("each field must be an object")
        path = item.get("path")
        if not isinstance(path, str):
            raise InvalidSchema("each field requires a JSON Pointer path string")
        segments = _parse_pointer(path)
        if not segments:
            raise InvalidSchema("field paths must be non-root JSON Pointers")
        if path in seen:
            raise InvalidSchema("field paths must be unique")
        seen.add(path)
        kind = item.get("kind")
        if not isinstance(kind, str) or kind not in _KINDS:
            raise InvalidSchema("kind must be categorical or numeric")
        fields.append((path, kind, segments))
    return fields


def _resolve(record: dict, segments: tuple[str, ...], error: type[ValueError]) -> Any:
    """Resolve a JSON Pointer with strict RFC 6901 array index handling."""
    node: Any = record
    for segment in segments:
        if isinstance(node, dict):
            if segment not in node:
                raise error("every field path must resolve on every record")
            node = node[segment]
        elif isinstance(node, list):
            if segment == "-" or not segment.isdigit():
                raise error("invalid array index in field path")
            if segment != "0" and segment[0] == "0":
                raise error("array indices must not have leading zeros")
            index = int(segment)
            if index >= len(node):
                raise error("every field path must resolve on every record")
            node = node[index]
        else:
            raise error("every field path must resolve on every record")
    if isinstance(node, (dict, list)):
        raise error("field paths must resolve to leaf values")
    return node


def _check_leaf(value: Any, kind: str, error: type[ValueError]) -> None:
    if kind == "categorical":
        # bool is an int subclass in Python, so check it before numbers.
        if value is not None and not isinstance(value, (str, bool)):
            raise error("categorical fields must be strings, booleans or null")
        return
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise error("numeric fields must be finite JSON numbers")
    if isinstance(value, float) and not math.isfinite(value):
        raise error("numeric fields must be finite JSON numbers")


def _extract_rows(
    records: list, fields: list[tuple[str, str, tuple[str, ...]]], error: type[ValueError]
) -> list[list]:
    rows: list[list] = []
    for record in records:
        if not isinstance(record, dict):
            raise error("each record must be an object")
        row = []
        for _path, kind, segments in fields:
            value = _resolve(record, segments, error)
            _check_leaf(value, kind, error)
            row.append(value)
        rows.append(row)
    return rows


def _scalar_key(value: Any) -> tuple[int, Any]:
    """Build a hashable key with JSON equality semantics.

    Tags keep the JSON types apart (true != 1, null != false) while ints
    and floats share a numeric tag keyed by their exact decimal value so
    that 1 and 1.0 compare equal.
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


def _decimal_number(value: Any) -> Decimal:
    if isinstance(value, int):
        return Decimal(value)
    return Decimal(str(value))


def _categorical_distance(real_values: list, synthetic_values: list) -> Decimal:
    """Total variation distance between the two empirical distributions."""
    real_counts: dict[tuple[int, Any], int] = {}
    for value in real_values:
        key = _scalar_key(value)
        real_counts[key] = real_counts.get(key, 0) + 1
    synthetic_counts: dict[tuple[int, Any], int] = {}
    for value in synthetic_values:
        key = _scalar_key(value)
        synthetic_counts[key] = synthetic_counts.get(key, 0) + 1
    real_total = Decimal(len(real_values))
    synthetic_total = Decimal(len(synthetic_values))
    distance = Decimal(0)
    for key in real_counts.keys() | synthetic_counts.keys():
        distance += abs(
            Decimal(real_counts.get(key, 0)) / real_total
            - Decimal(synthetic_counts.get(key, 0)) / synthetic_total
        )
    return distance / 2


def _numeric_distance(real_values: list, synthetic_values: list) -> Decimal:
    """Kolmogorov-Smirnov distance between the two empirical CDFs."""
    real_sorted = sorted(_decimal_number(value) for value in real_values)
    synthetic_sorted = sorted(_decimal_number(value) for value in synthetic_values)
    real_total = Decimal(len(real_sorted))
    synthetic_total = Decimal(len(synthetic_sorted))
    distance = Decimal(0)
    real_index = 0
    synthetic_index = 0
    for point in sorted(set(real_sorted) | set(synthetic_sorted)):
        while real_index < len(real_sorted) and real_sorted[real_index] <= point:
            real_index += 1
        while synthetic_index < len(synthetic_sorted) and synthetic_sorted[synthetic_index] <= point:
            synthetic_index += 1
        gap = abs(
            Decimal(real_index) / real_total - Decimal(synthetic_index) / synthetic_total
        )
        if gap > distance:
            distance = gap
    return distance


def synthetic_evaluate_request(payload: Any) -> dict:
    """Validate a /v1/synthetic/evaluate payload and score its utility."""
    real_records, synthetic_records, raw_fields = _validate_payload(payload)
    fields = _validate_fields(raw_fields)
    real_rows = _extract_rows(real_records, fields, InvalidRealRecords)
    synthetic_rows = _extract_rows(synthetic_records, fields, InvalidSyntheticRecords)

    results: list[dict] = []
    with localcontext() as context:
        context.prec = 60
        utilities: list[Decimal] = []
        for index, (path, kind, _segments) in enumerate(fields):
            real_column = [row[index] for row in real_rows]
            synthetic_column = [row[index] for row in synthetic_rows]
            if kind == "categorical":
                distance = _categorical_distance(real_column, synthetic_column)
            else:
                distance = _numeric_distance(real_column, synthetic_column)
            utility = Decimal(1) - distance
            utilities.append(utility)
            results.append(
                {
                    "path": path,
                    "kind": kind,
                    "distance": _round6(distance),
                    "utility": _round6(utility),
                }
            )
        overall_utility = sum(utilities) / Decimal(len(utilities))

        real_keys = {tuple(_scalar_key(value) for value in row) for row in real_rows}
        exact_match_count = sum(
            1
            for row in synthetic_rows
            if tuple(_scalar_key(value) for value in row) in real_keys
        )
        exact_match_rate = Decimal(exact_match_count) / Decimal(len(synthetic_rows))

    results.sort(key=lambda field: field["path"])
    return {
        "real_count": len(real_records),
        "synthetic_count": len(synthetic_records),
        "fields": results,
        "overall_utility": _round6(overall_utility),
        "exact_match_count": exact_match_count,
        "exact_match_rate": _round6(exact_match_rate),
    }
