"""Differentially private aggregate releases.

Pure and request-scoped like the other query capabilities: records are
only read from the current payload and nothing (records, keys, budget
ledger) is retained between requests. Unlike the small-group protected
aggregate, every *public* partition in ``partitions`` is released, even
when its true count is zero; records that do not match a public
partition are ignored.

Each released value carries Laplace noise whose scale is
``sensitivity / epsilon`` (count sensitivity 1, sum sensitivity
``upper - lower``). The noise is deterministic: it is derived with an
HMAC-SHA256 PRF keyed by the request ``noise_secret`` over a fixed
version, the non-empty ``release_id``, the type-tagged partition key
and the metric name. Retrying an identical release therefore yields
identical noise, while changing the release identifier, partition or
metric draws independent noise.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import math
import re
import struct
from decimal import Decimal, localcontext
from typing import Any

from .classifier import (
    InvalidRequest,
    InvalidSchema,
    _parse_pointer as _parse_json_pointer,
    _validate_records,
)
from .aggregate import (
    InvalidGroupBy,
    InvalidMetric,
    _decimal_number,
    _resolve,
    _round6,
)

#: Fixed domain-separation/version tag mixed into every noise derivation.
NOISE_VERSION = "privacare.differential.v1"

_BASE64URL_RE = re.compile(r"^[A-Za-z0-9_-]+$")

_METRIC_TYPES = frozenset(("count", "sum"))


class InvalidPartition(ValueError):
    """The partitions array or one of its public keys is malformed."""


class InvalidPrivacyBudget(ValueError):
    """The budget or per-metric epsilon is malformed, or balance is low."""


class InvalidNoiseConfig(ValueError):
    """The release_id or noise_secret is malformed."""


def _is_finite_number(value: Any) -> bool:
    return (
        not isinstance(value, bool)
        and isinstance(value, (int, float))
        and (not isinstance(value, float) or math.isfinite(value))
    )


def _validate_group_by(raw: Any, records: list[dict]) -> list[tuple[str, ...]]:
    # A null (including an omitted field) means the single global grouping.
    if raw is None:
        return []
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
        try:
            segments = _parse_json_pointer(item)
        except InvalidSchema as exc:
            raise InvalidGroupBy(str(exc)) from exc
        pointers.append(segments)
    for record in records:
        for segments in pointers:
            value = _resolve(record, segments, InvalidGroupBy)
            _key_element(value, InvalidGroupBy)
    return pointers


def _canonical_decimal(value: Decimal) -> bytes:
    """Fixed-point decimal text with trailing zeros removed (1.0 == 1.00)."""
    text = format(value.normalize(), "f")
    if text == "-0":
        text = "0"
    return text.encode("ascii")


def _key_element(value: Any, error: type[ValueError]) -> tuple[int, bytes]:
    """Tag a scalar with JSON equality semantics and canonical bytes.

    Types never compare across tags (null != false != 0, strings stay
    distinct) while ints and floats share the numeric tag keyed by their
    canonical decimal value so 1 and 1.0 form a single key.
    """
    if value is None:
        return (0, b"")
    if isinstance(value, bool):
        return (1, b"1" if value else b"0")
    if isinstance(value, int):
        return (2, _canonical_decimal(Decimal(value)))
    if isinstance(value, float):
        if not math.isfinite(value):
            raise error("group/partition values must be finite scalars")
        return (2, _canonical_decimal(Decimal(str(value))))
    if isinstance(value, str):
        return (3, value.encode("utf-8"))
    raise error("group/partition keys must be scalar values")


def _signature(elements: list[Any], error: type[ValueError]) -> tuple[tuple[int, bytes], ...]:
    return tuple(_key_element(value, error) for value in elements)


def _validate_partitions(raw: Any, width: int) -> list[tuple[list[Any], tuple[tuple[int, bytes], ...]]]:
    if not isinstance(raw, list) or not raw:
        raise InvalidPartition("partitions must be a non-empty array")
    partitions: list[tuple[list[Any], tuple[tuple[int, bytes], ...]]] = []
    seen: set[tuple[tuple[int, bytes], ...]] = set()
    for key in raw:
        if not isinstance(key, list) or len(key) != width:
            raise InvalidPartition(
                "each partition key must be an array matching group_by in length"
            )
        signature = _signature(key, InvalidPartition)
        if signature in seen:
            raise InvalidPartition("partitions must not contain duplicate keys")
        seen.add(signature)
        partitions.append((key, signature))
    return partitions


def _validate_metric_shapes(raw: Any, records: list[dict]) -> list[dict[str, Any]]:
    """Validate everything about a metric except its epsilon (budget error)."""
    if not isinstance(raw, list) or not raw:
        raise InvalidMetric("metrics must be a non-empty array")
    metrics: list[dict[str, Any]] = []
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
        metric_type = item.get("type")
        if not isinstance(metric_type, str) or metric_type not in _METRIC_TYPES:
            raise InvalidMetric("metric type must be count or sum")
        if metric_type == "count":
            if "field" in item or "lower" in item or "upper" in item:
                raise InvalidMetric("count metrics only carry name, type and epsilon")
            metrics.append({"name": name, "type": "count"})
            continue
        field = item.get("field")
        if not isinstance(field, str) or not field or not field.startswith("/"):
            raise InvalidMetric("sum metrics require a non-root JSON Pointer field")
        try:
            segments = _parse_json_pointer(field)
        except InvalidSchema as exc:
            raise InvalidMetric(str(exc)) from exc
        if not segments:
            raise InvalidMetric("sum metrics require a non-root JSON Pointer field")
        lower = item.get("lower")
        upper = item.get("upper")
        if not _is_finite_number(lower) or not _is_finite_number(upper):
            raise InvalidMetric("sum bounds must be finite JSON numbers")
        lower_d = _decimal_number(lower)
        upper_d = _decimal_number(upper)
        if lower_d >= upper_d:
            raise InvalidMetric("lower must be strictly less than upper")
        for record in records:
            value = _resolve(record, segments, InvalidMetric)
            if not _is_finite_number(value):
                raise InvalidMetric(
                    "metric fields must be finite JSON numbers on every record"
                )
        metrics.append(
            {
                "name": name,
                "type": "sum",
                "segments": segments,
                "lower": lower_d,
                "upper": upper_d,
            }
        )
    return metrics


def _validate_epsilon(raw: Any) -> Decimal:
    if not _is_finite_number(raw):
        raise InvalidPrivacyBudget("epsilon must be a finite JSON number")
    epsilon = _decimal_number(raw)
    if epsilon <= 0 or epsilon > Decimal(10):
        raise InvalidPrivacyBudget("epsilon must be greater than 0 and at most 10")
    return epsilon


def _validate_budget(raw: Any) -> tuple[Decimal, Decimal]:
    if not isinstance(raw, dict):
        raise InvalidPrivacyBudget("budget must be an object with limit and spent")
    limit = raw.get("limit")
    spent = raw.get("spent")
    if not _is_finite_number(limit) or not _is_finite_number(spent):
        raise InvalidPrivacyBudget("limit and spent must be finite non-negative numbers")
    limit_d = _decimal_number(limit)
    spent_d = _decimal_number(spent)
    if limit_d < 0 or spent_d < 0:
        raise InvalidPrivacyBudget("limit and spent must be non-negative")
    return limit_d, spent_d


def _decode_secret(raw: Any) -> bytes:
    """Validate an unpadded base64url string decoding to at least 32 bytes."""
    if not isinstance(raw, str) or not _BASE64URL_RE.fullmatch(raw):
        raise InvalidNoiseConfig("noise_secret must be an unpadded base64url string")
    if len(raw) % 4 == 1:
        raise InvalidNoiseConfig("noise_secret must be an unpadded base64url string")
    padded = raw + "=" * (-len(raw) % 4)
    try:
        key = base64.urlsafe_b64decode(padded.encode("ascii"))
    except (binascii.Error, ValueError):
        raise InvalidNoiseConfig(
            "noise_secret must be an unpadded base64url string"
        ) from None
    if len(key) < 32:
        raise InvalidNoiseConfig("noise_secret must decode to at least 32 bytes")
    return key


def _validate_noise_config(payload: dict) -> tuple[str, bytes]:
    release_id = payload.get("release_id")
    if not isinstance(release_id, str) or not release_id:
        raise InvalidNoiseConfig("release_id must be a non-empty string")
    secret = _decode_secret(payload.get("noise_secret"))
    return release_id, secret


def _lprefixed(data: bytes) -> bytes:
    return struct.pack(">Q", len(data)) + data


def _laplace_draw(
    secret: bytes,
    release_id: str,
    signature: tuple[tuple[int, bytes], ...],
    metric_name: str,
) -> Decimal:
    """Draw one deterministic standard-Laplace sample for release/key/metric."""
    message = b"".join(
        (
            _lprefixed(NOISE_VERSION.encode("utf-8")),
            _lprefixed(release_id.encode("utf-8")),
            struct.pack(">Q", len(signature)),
        )
    )
    for tag, payload in signature:
        message += struct.pack(">B", tag) + _lprefixed(payload)
    message += _lprefixed(metric_name.encode("utf-8"))
    digest = hmac.new(secret, message, hashlib.sha256).digest()
    # Midpoint of the 256-bit PRF quantile bucket: a uniform draw in (0, 1).
    uniform = (Decimal(int.from_bytes(digest, "big")) + Decimal("0.5")) / (1 << 256)
    u = float(uniform)
    # Inverse CDF of the standard Laplace distribution: sgn(u-1/2)*ln(2|u-1/2|).
    if u < 0.5:
        draw = math.log(2.0 * u)
    else:
        draw = -math.log(2.0 * (1.0 - u))
    return Decimal(repr(draw))


def differential_aggregate_request(payload: Any) -> dict:
    """Validate a /v1/query/differential-aggregate payload and release it."""
    records = _validate_records(payload)
    group_pointers = _validate_group_by(payload.get("group_by"), records)
    partitions = _validate_partitions(payload.get("partitions"), len(group_pointers))
    raw_metrics = payload.get("metrics")
    metrics = _validate_metric_shapes(raw_metrics, records)
    limit, spent = _validate_budget(payload.get("budget"))
    epsilons = [_validate_epsilon(item.get("epsilon")) for item in raw_metrics]
    # All structural checks (including the noise configuration) pass before
    # the balance gate, so an under-budget request never publishes anything.
    release_id, secret = _validate_noise_config(payload)

    with localcontext() as context:
        context.prec = 60
        consumed = sum(epsilons, Decimal(0))
        cumulative_spent = spent + consumed
        if cumulative_spent > limit:
            raise InvalidPrivacyBudget("remaining privacy budget is insufficient")
        remaining = limit - cumulative_spent

        # Accumulate true values for public partitions only; records whose
        # key is not published are ignored.
        accum: dict[tuple, dict[str, Any]] = {}
        for _key, signature in partitions:
            accum[signature] = {
                "count": 0,
                "sums": [
                    Decimal(0) if metric["type"] == "sum" else None
                    for metric in metrics
                ],
            }
        for record in records:
            values = [
                _resolve(record, segments, InvalidGroupBy)
                for segments in group_pointers
            ]
            signature = _signature(values, InvalidGroupBy)
            entry = accum.get(signature)
            if entry is None:
                continue
            entry["count"] += 1
            for index, metric in enumerate(metrics):
                if metric["type"] == "sum":
                    value = _decimal_number(
                        _resolve(record, metric["segments"], InvalidMetric)
                    )
                    if value < metric["lower"]:
                        value = metric["lower"]
                    elif value > metric["upper"]:
                        value = metric["upper"]
                    entry["sums"][index] += value

        released: list[dict] = []
        for key, signature in partitions:
            entry = accum[signature]
            metric_values: dict[str, Any] = {}
            for index, metric in enumerate(metrics):
                scale = (
                    Decimal(1)
                    if metric["type"] == "count"
                    else metric["upper"] - metric["lower"]
                ) / epsilons[index]
                if metric["type"] == "count":
                    true_value = Decimal(entry["count"])
                else:
                    true_value = entry["sums"][index]
                draw = _laplace_draw(secret, release_id, signature, metric["name"])
                noisy = true_value + scale * draw
                if metric["type"] == "count" and noisy < 0:
                    noisy = Decimal(0)
                metric_values[metric["name"]] = _round6(noisy)
            released.append({"key": key, "metrics": metric_values})

    return {
        "partitions": released,
        "budget": {
            "consumed": _round6(consumed),
            "spent": _round6(cumulative_spent),
            "remaining": _round6(remaining),
        },
    }
