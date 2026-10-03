"""Small-group protected aggregate queries.

Pure and request-scoped like the other capabilities: records are only
read from the current payload, the caller's data is never mutated and
nothing is retained between requests. Records are partitioned by the
ordered scalar values found at the ``group_by`` JSON Pointers, and only
groups whose size reaches ``minimum_group_size`` are returned; smaller
groups are suppressed wholesale so their keys, sizes, metrics and
values never leave the process.
"""

from __future__ import annotations

import math
from decimal import Decimal, ROUND_HALF_UP, localcontext
from typing import Any

from .classifier import (
    InvalidRequest,
    InvalidSchema,
    _parse_pointer as _parse_json_pointer,
    _validate_records,
)

_QUANTUM = Decimal("0.000001")

_OPERATIONS = frozenset(("count", "sum", "average"))


class InvalidGroupBy(ValueError):
    """group_by is malformed or does not resolve to scalar values."""


class InvalidMetric(ValueError):
    """A metric definition is malformed or its field is not finite numeric."""


class InvalidThreshold(ValueError):
    """minimum_group_size is not a JSON integer in [2, 1000]."""


def _round6(value: Decimal) -> float:
    """Round a decimal to six places, half up, and emit as a JSON number."""
    return float(value.quantize(_QUANTUM, rounding=ROUND_HALF_UP))


def _parse_pointer(raw: str, error: type[ValueError]) -> tuple[str, ...]:
    try:
        return _parse_json_pointer(raw)
    except InvalidSchema as exc:
        raise error(str(exc)) from exc


def _resolve(record: dict, segments: tuple[str, ...], error: type[ValueError]) -> Any:
    """Resolve a JSON Pointer with strict RFC 6901 array index handling."""
    node: Any = record
    for segment in segments:
        if isinstance(node, dict):
            if segment not in node:
                raise error("every pointer must resolve on every record")
            node = node[segment]
        elif isinstance(node, list):
            if segment == "-" or not segment.isdigit():
                raise error("invalid array index in pointer")
            if segment != "0" and segment[0] == "0":
                raise error("array indices must not have leading zeros")
            index = int(segment)
            if index >= len(node):
                raise error("every pointer must resolve on every record")
            node = node[index]
        else:
            raise error("every pointer must resolve on every record")
    return node


def _group_signature_value(value: Any) -> tuple[int, Any]:
    """Tag a resolved group-by value with JSON equality semantics.

    Types never compare across tags (null != false != 0, strings stay
    distinct) while ints and floats share the numeric tag keyed by their
    decimal value so 1 and 1.0 land in the same group.
    """
    if value is None:
        return (0, 0)
    if isinstance(value, bool):
        return (1, value)
    if isinstance(value, int):
        return (2, Decimal(value))
    if isinstance(value, float):
        if not math.isfinite(value):
            raise InvalidGroupBy("group_by values must be finite scalars")
        return (2, Decimal(str(value)))
    if isinstance(value, str):
        return (3, value)
    raise InvalidGroupBy("group_by pointers must resolve to scalar values")


def _require_finite_number(value: Any) -> None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise InvalidMetric("metric fields must be finite JSON numbers on every record")
    if isinstance(value, float) and not math.isfinite(value):
        raise InvalidMetric("metric fields must be finite JSON numbers on every record")


def _decimal_number(value: Any) -> Decimal:
    if isinstance(value, int):
        return Decimal(value)
    return Decimal(str(value))


def _validate_group_by(raw: Any, records: list[dict]) -> list[tuple[str, ...]]:
    if not isinstance(raw, list):
        raise InvalidGroupBy("group_by must be an array of JSON Pointer strings")
    pointers: list[tuple[str, ...]] = []
    seen: set[str] = set()
    for item in raw:
        if not isinstance(item, str):
            raise InvalidGroupBy("group_by entries must be JSON Pointer strings")
        if item in seen:
            raise InvalidGroupBy("group_by must not contain duplicates")
        seen.add(item)
        pointers.append(_parse_pointer(item, InvalidGroupBy))
    # Every non-empty pointer must resolve to an allowed scalar on every
    # record; the root pointer resolves to the record container and fails.
    for record in records:
        for segments in pointers:
            value = _resolve(record, segments, InvalidGroupBy)
            _group_signature_value(value)
    return pointers


def _validate_metrics(raw: Any, records: list[dict]) -> list[tuple[str, str, tuple[str, ...] | None]]:
    if not isinstance(raw, list) or not raw:
        raise InvalidMetric("metrics must be a non-empty array")
    metrics: list[tuple[str, str, tuple[str, ...] | None]] = []
    names: set[str] = set()
    for item in raw:
        if not isinstance(item, dict):
            raise InvalidMetric("each metric must be an object")
        name = item.get("name")
        if not isinstance(name, str) or not name:
            raise InvalidMetric("each metric needs a unique non-empty name")
        if name in names:
            raise InvalidMetric("metric names must be unique")
        names.add(name)
        operation = item.get("operation")
        if not isinstance(operation, str) or operation not in _OPERATIONS:
            raise InvalidMetric("operation must be count, sum or average")
        if operation == "count":
            if "field" in item:
                raise InvalidMetric("count metrics must not carry a field")
            metrics.append((name, operation, None))
            continue
        field = item.get("field")
        if not isinstance(field, str) or not field or not field.startswith("/"):
            raise InvalidMetric(
                "sum and average metrics require a non-root JSON Pointer field"
            )
        segments = _parse_pointer(field, InvalidMetric)
        if not segments:
            raise InvalidMetric(
                "sum and average metrics require a non-root JSON Pointer field"
            )
        for record in records:
            _require_finite_number(_resolve(record, segments, InvalidMetric))
        metrics.append((name, operation, segments))
    return metrics


def _validate_threshold(raw: Any) -> int:
    # bool is an int subclass in Python, but JSON true/false is not a number.
    if isinstance(raw, bool) or not isinstance(raw, int) or not 2 <= raw <= 1000:
        raise InvalidThreshold("minimum_group_size must be a JSON integer between 2 and 1000")
    return raw


def aggregate_query_request(payload: Any) -> dict:
    """Validate a /v1/query/aggregate payload and run the grouped statistics."""
    records = _validate_records(payload)
    group_pointers = _validate_group_by(payload.get("group_by"), records)
    metrics = _validate_metrics(payload.get("metrics"), records)
    threshold = _validate_threshold(payload.get("minimum_group_size"))

    # Accumulate in first-appearance order; signatures carry JSON equality.
    order: list[tuple[tuple[int, Any], ...]] = []
    groups: dict[tuple, dict[str, Any]] = {}
    with localcontext() as context:
        context.prec = 60
        for record in records:
            values = [_resolve(record, segments, InvalidGroupBy) for segments in group_pointers]
            signature = tuple(_group_signature_value(value) for value in values)
            entry = groups.get(signature)
            if entry is None:
                entry = {
                    "key": values,
                    "size": 0,
                    "sums": [Decimal(0) for _ in metrics],
                }
                groups[signature] = entry
                order.append(signature)
            entry["size"] += 1
            for index, (_name, operation, segments) in enumerate(metrics):
                if segments is not None:
                    value = _resolve(record, segments, InvalidMetric)
                    entry["sums"][index] += _decimal_number(value)

        visible_groups: list[dict] = []
        suppressed_group_count = 0
        for signature in order:
            entry = groups[signature]
            size = entry["size"]
            if size < threshold:
                # Nothing about a suppressed group is exposed.
                suppressed_group_count += 1
                continue
            metric_values: dict[str, Any] = {}
            for index, (name, operation, _segments) in enumerate(metrics):
                if operation == "count":
                    metric_values[name] = size
                elif operation == "sum":
                    metric_values[name] = _round6(entry["sums"][index])
                else:
                    metric_values[name] = _round6(entry["sums"][index] / Decimal(size))
            visible_groups.append(
                {"key": entry["key"], "size": size, "metrics": metric_values}
            )

    return {"groups": visible_groups, "suppressed_group_count": suppressed_group_count}
