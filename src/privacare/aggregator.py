"""Thresholded group aggregation over request records.

Pure and request-scoped, like the classifier and the risk measurer: the
payload is only read, never mutated, and nothing is retained between
requests. Groups come from the ordered combination of the scalar values at
the caller-supplied group_by JSON Pointers; only groups reaching
minimum_group_size are returned, smaller groups contribute nothing but
their count to suppressed_group_count.
"""

from __future__ import annotations

import math
from decimal import Decimal, ROUND_HALF_UP, localcontext
from typing import Any

from .classifier import InvalidSchema, _parse_pointer, _validate_records

_OPERATIONS = ("count", "sum", "average")

_QUANTUM = Decimal("0.000001")


class InvalidGroupBy(ValueError):
    """The group_by array is malformed or does not resolve to scalars."""


class InvalidMetric(ValueError):
    """A metric entry is malformed or its field does not resolve to numbers."""


class InvalidThreshold(ValueError):
    """minimum_group_size is not a JSON integer between 2 and 1000."""


def _validate_group_by(raw: Any) -> list[tuple[str, ...]]:
    if not isinstance(raw, list):
        raise InvalidGroupBy("group_by must be an array of JSON Pointers")
    pointers: list[tuple[str, ...]] = []
    seen: set[str] = set()
    for item in raw:
        if not isinstance(item, str):
            raise InvalidGroupBy("group_by entries must be JSON Pointer strings")
        try:
            segments = _parse_pointer(item)
        except InvalidSchema as exc:
            raise InvalidGroupBy(str(exc)) from exc
        if item in seen:
            raise InvalidGroupBy("group_by must not contain duplicates")
        seen.add(item)
        pointers.append(segments)
    return pointers


def _validate_metrics(raw: Any) -> list[tuple[str, str, tuple[str, ...] | None]]:
    if not isinstance(raw, list) or not raw:
        raise InvalidMetric("metrics must be a non-empty array")
    metrics: list[tuple[str, str, tuple[str, ...] | None]] = []
    seen: set[str] = set()
    for entry in raw:
        if not isinstance(entry, dict):
            raise InvalidMetric("each metric must be an object")
        name = entry.get("name")
        if not isinstance(name, str) or not name:
            raise InvalidMetric("metric name must be a non-empty string")
        if name in seen:
            raise InvalidMetric("metric names must be unique")
        seen.add(name)
        operation = entry.get("operation")
        if operation not in _OPERATIONS:
            raise InvalidMetric("metric operation must be count, sum or average")
        if operation == "count":
            if "field" in entry:
                raise InvalidMetric("count metrics must not carry a field")
            metrics.append((name, operation, None))
            continue
        field = entry.get("field")
        if not isinstance(field, str):
            raise InvalidMetric("sum and average metrics must carry a field pointer")
        try:
            segments = _parse_pointer(field)
        except InvalidSchema as exc:
            raise InvalidMetric(str(exc)) from exc
        if not segments:
            raise InvalidMetric("metric field must be a non-root JSON Pointer")
        metrics.append((name, operation, segments))
    return metrics


def _validate_threshold(raw: Any) -> int:
    # bool is an int subclass in Python, but JSON true/false is not a number.
    if isinstance(raw, bool) or not isinstance(raw, int) or not 2 <= raw <= 1000:
        raise InvalidThreshold("minimum_group_size must be a JSON integer between 2 and 1000")
    return raw


def _descend(record: dict, segments: tuple[str, ...], error: type[InvalidGroupBy] | type[InvalidMetric]) -> Any:
    """Resolve a JSON Pointer, following RFC 6901 array index rules.

    "0" alone may have a leading zero, every other index may not, and "-"
    never resolves.
    """
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


def _resolve_scalar(record: dict, segments: tuple[str, ...]) -> Any:
    node = _descend(record, segments, InvalidGroupBy)
    if isinstance(node, (dict, list)):
        raise InvalidGroupBy("group_by pointers must resolve to scalar values")
    if isinstance(node, float) and not math.isfinite(node):
        raise InvalidGroupBy("group_by pointers must resolve to finite values")
    return node


def _resolve_number(record: dict, segments: tuple[str, ...]) -> Decimal:
    node = _descend(record, segments, InvalidMetric)
    # JSON booleans are not numbers, and only finite numbers may aggregate.
    if isinstance(node, bool) or not isinstance(node, (int, float)):
        raise InvalidMetric("metric fields must resolve to JSON numbers")
    if isinstance(node, float):
        if not math.isfinite(node):
            raise InvalidMetric("metric fields must resolve to finite JSON numbers")
        return Decimal(str(node))
    return Decimal(node)


def _scalar_key(value: Any) -> tuple[int, Any]:
    """Build a hashable group key with JSON equality semantics.

    Tags keep the JSON types apart (true != 1, null != false) while ints
    and floats share a numeric tag keyed by their exact decimal value so
    that 1 and 1.0 land in the same group.
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


def _precision(value: Decimal) -> int:
    """Significant digits needed to keep six fractional places of a value
    this large, never below the default decimal context precision."""
    return max(28, value.adjusted() + 8)


def _round6(value: Decimal) -> float:
    """Round a decimal to six places, half up, and emit as a JSON number."""
    with localcontext() as ctx:
        ctx.prec = _precision(value)
        return float(value.quantize(_QUANTUM, rounding=ROUND_HALF_UP))


def _average(total: Decimal, size: int) -> Decimal:
    """Divide without losing the digits the six-place rounding needs."""
    with localcontext() as ctx:
        ctx.prec = _precision(total)
        return total / Decimal(size)


def aggregate_request(payload: Any) -> dict:
    """Validate a /v1/query/aggregate payload and aggregate every record."""
    records = _validate_records(payload)
    group_pointers = _validate_group_by(payload.get("group_by"))
    # Resolve each stage before validating the next so the error code always
    # points at the earliest offending field; resolving up front also means
    # a validation failure can never yield partial results.
    resolved_keys = [
        [_resolve_scalar(record, segments) for segments in group_pointers]
        for record in records
    ]
    metrics = _validate_metrics(payload.get("metrics"))
    numeric_metrics = [segments for _name, _operation, segments in metrics if segments is not None]
    resolved_numbers = [
        [_resolve_number(record, segments) for segments in numeric_metrics]
        for record in records
    ]
    threshold = _validate_threshold(payload.get("minimum_group_size"))

    groups: dict[tuple, dict] = {}
    for record_index, values in enumerate(resolved_keys):
        key = tuple(_scalar_key(value) for value in values)
        group = groups.get(key)
        if group is None:
            group = {
                "values": values,
                "size": 0,
                "totals": [Decimal(0) for _segments in numeric_metrics],
            }
            groups[key] = group
        group["size"] += 1
        for metric_index, number in enumerate(resolved_numbers[record_index]):
            group["totals"][metric_index] += number

    visible: list[dict] = []
    suppressed = 0
    for group in groups.values():
        size = group["size"]
        if size < threshold:
            suppressed += 1
            continue
        results: dict[str, Any] = {}
        numeric_index = 0
        for name, operation, segments in metrics:
            if operation == "count":
                results[name] = size
                continue
            total = group["totals"][numeric_index]
            numeric_index += 1
            if operation == "sum":
                results[name] = _round6(total)
            else:
                results[name] = _round6(_average(total, size))
        visible.append({"key": group["values"], "size": size, "metrics": results})
    return {"groups": visible, "suppressed_group_count": suppressed}
