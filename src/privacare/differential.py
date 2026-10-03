"""Differentially private aggregate release over public partitions.

Pure and request-scoped like the other capabilities: records, the noise
secret and the privacy budget are only read from the current payload,
nothing is retained between requests and the caller's data is never
mutated. Records are matched against the caller-supplied public
partition keys; unmatched records are ignored and every public
partition is reported in input order, including partitions whose true
count is zero. Each metric gets Laplace noise scaled to its sensitivity
over its epsilon, derived deterministically from the noise secret, a
fixed version, the release identifier, the typed partition key and the
metric name — so retrying the same release yields identical numbers
while any identifier change draws independent noise.
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

from .aggregate import (
    InvalidGroupBy,
    InvalidMetric,
    _decimal_number,
    _group_signature_value,
    _parse_pointer,
    _require_finite_number,
    _resolve,
    _round6,
    _validate_group_by,
)
from .classifier import _validate_records

#: Fixed domain-separation tag baked into every noise derivation.
_NOISE_VERSION = "privacare.differential.v1"

_BASE64URL_RE = re.compile(r"^[A-Za-z0-9_-]+$")

_OPERATIONS = frozenset(("count", "sum"))


class InvalidPartition(ValueError):
    """partitions is malformed, mistyped or contains duplicate keys."""


class InvalidPrivacyBudget(ValueError):
    """budget or an epsilon is malformed, or the balance is insufficient."""


class InvalidNoiseConfig(ValueError):
    """release_id or noise_secret is malformed."""


def _validate_partitions(raw: Any, width: int) -> list[tuple[list, tuple]]:
    """Validate the public partition keys into (key, signature) pairs."""
    if not isinstance(raw, list) or not raw:
        raise InvalidPartition("partitions must be a non-empty array")
    keys: list[tuple[list, tuple]] = []
    seen: set[tuple] = set()
    for item in raw:
        if not isinstance(item, list) or len(item) != width:
            raise InvalidPartition("each partition key must match the group_by width")
        signature = tuple(_partition_scalar(value) for value in item)
        if signature in seen:
            raise InvalidPartition("partition keys must not contain duplicates")
        seen.add(signature)
        keys.append((item, signature))
    return keys


def _partition_scalar(value: Any) -> tuple[int, Any]:
    """Tag a partition key element with the grouping JSON equality semantics."""
    try:
        return _group_signature_value(value)
    except InvalidGroupBy:
        raise InvalidPartition(
            "partition keys must contain only strings, finite numbers, booleans or null"
        ) from None


def _validate_bound(raw: Any, label: str) -> Decimal:
    if isinstance(raw, bool) or not isinstance(raw, (int, float)):
        raise InvalidMetric(f"{label} must be a finite JSON number")
    if isinstance(raw, float) and not math.isfinite(raw):
        raise InvalidMetric(f"{label} must be a finite JSON number")
    return _decimal_number(raw)


def _validate_metrics(
    raw: Any, records: list[dict]
) -> list[tuple[str, str, tuple[str, ...] | None, Decimal | None, Decimal | None, Any]]:
    """Structural metric validation; epsilon is budget-checked separately."""
    if not isinstance(raw, list) or not raw:
        raise InvalidMetric("metrics must be a non-empty array")
    metrics: list[tuple[str, str, tuple[str, ...] | None, Decimal | None, Decimal | None, Any]] = []
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
            raise InvalidMetric("operation must be count or sum")
        epsilon = item.get("epsilon")
        if operation == "count":
            if "field" in item or "lower" in item or "upper" in item:
                raise InvalidMetric("count metrics must not carry a field or bounds")
            metrics.append((name, operation, None, None, None, epsilon))
            continue
        field = item.get("field")
        if not isinstance(field, str) or not field or not field.startswith("/"):
            raise InvalidMetric("sum metrics require a non-root JSON Pointer field")
        segments = _parse_pointer(field, InvalidMetric)
        if not segments:
            raise InvalidMetric("sum metrics require a non-root JSON Pointer field")
        lower = _validate_bound(item.get("lower"), "lower")
        upper = _validate_bound(item.get("upper"), "upper")
        if not lower < upper:
            raise InvalidMetric("lower must be less than upper")
        for record in records:
            _require_finite_number(_resolve(record, segments, InvalidMetric))
        metrics.append((name, operation, segments, lower, upper, epsilon))
    return metrics


def _validate_epsilon(raw: Any) -> Decimal:
    if isinstance(raw, bool) or not isinstance(raw, (int, float)):
        raise InvalidPrivacyBudget("epsilon must be a JSON number greater than 0 and at most 10")
    if isinstance(raw, float) and not math.isfinite(raw):
        raise InvalidPrivacyBudget("epsilon must be a JSON number greater than 0 and at most 10")
    value = _decimal_number(raw)
    if value <= 0 or value > 10:
        raise InvalidPrivacyBudget("epsilon must be greater than 0 and at most 10")
    return value


def _validate_budget_number(raw: Any, label: str) -> Decimal:
    if isinstance(raw, bool) or not isinstance(raw, (int, float)):
        raise InvalidPrivacyBudget(f"budget {label} must be a non-negative finite number")
    if isinstance(raw, float) and not math.isfinite(raw):
        raise InvalidPrivacyBudget(f"budget {label} must be a non-negative finite number")
    value = _decimal_number(raw)
    if value < 0:
        raise InvalidPrivacyBudget(f"budget {label} must be a non-negative finite number")
    return value


def _validate_budget(raw: Any) -> tuple[Decimal, Decimal]:
    if not isinstance(raw, dict):
        raise InvalidPrivacyBudget("budget must be an object")
    return (
        _validate_budget_number(raw.get("limit"), "limit"),
        _validate_budget_number(raw.get("spent"), "spent"),
    )


def _validate_release_id(raw: Any) -> str:
    if not isinstance(raw, str) or not raw:
        raise InvalidNoiseConfig("release_id must be a non-empty string")
    return raw


def _decode_noise_secret(raw: Any) -> bytes:
    """Validate an unpadded base64url string decoding to at least 32 bytes."""
    if not isinstance(raw, str) or not _BASE64URL_RE.fullmatch(raw):
        raise InvalidNoiseConfig("noise_secret must be an unpadded base64url string")
    # A length of 4n+1 cannot occur in valid (unpadded) base64.
    if len(raw) % 4 == 1:
        raise InvalidNoiseConfig("noise_secret must be an unpadded base64url string")
    padded = raw + "=" * (-len(raw) % 4)
    try:
        secret = base64.urlsafe_b64decode(padded.encode("ascii"))
    except (binascii.Error, ValueError):
        raise InvalidNoiseConfig("noise_secret must be an unpadded base64url string") from None
    if len(secret) < 32:
        raise InvalidNoiseConfig("noise_secret must decode to at least 32 bytes")
    return secret


def _canonical_decimal(value: Decimal) -> str:
    """Canonical text for a numeric key element so 1 and 1.0 hash alike."""
    if value == 0:
        return "0"
    with localcontext() as context:
        context.prec = 60
        return str(value.normalize())


def _encode_key_element(signature: tuple[int, Any]) -> str:
    """Type-tagged canonical encoding of one partition key element."""
    tag, value = signature
    if tag == 0:
        return "null"
    if tag == 1:
        return "bool:true" if value else "bool:false"
    if tag == 2:
        return "num:" + _canonical_decimal(value)
    return "str:" + value


def _laplace_noise(
    secret: bytes,
    release_id: str,
    key_signature: tuple,
    metric_name: str,
    scale: float,
) -> float:
    """Deterministic Laplace draw via inverse CDF over an HMAC-derived uniform."""
    def part(data: bytes) -> bytes:
        return struct.pack(">I", len(data)) + data

    message = part(_NOISE_VERSION.encode("utf-8")) + part(release_id.encode("utf-8"))
    for element in key_signature:
        message += part(_encode_key_element(element).encode("utf-8"))
    message += part(metric_name.encode("utf-8"))
    digest = hmac.new(secret, message, hashlib.sha256).digest()
    uniform = (int.from_bytes(digest[:8], "big") + 0.5) / 2**64
    if uniform < 0.5:
        return scale * math.log(2 * uniform)
    return -scale * math.log(2 * (1 - uniform))


def differential_aggregate_request(payload: Any) -> dict:
    """Validate a /v1/query/differential-aggregate payload and release it."""
    records = _validate_records(payload)
    group_pointers = _validate_group_by(payload.get("group_by"), records)
    partitions = _validate_partitions(payload.get("partitions"), len(group_pointers))
    metrics = _validate_metrics(payload.get("metrics"), records)
    epsilons = [_validate_epsilon(metric[5]) for metric in metrics]
    limit, spent = _validate_budget(payload.get("budget"))
    # The release costs the sum of the metric epsilons, independent of the
    # number of partitions; nothing is published when the balance is short.
    consumed = sum(epsilons, Decimal(0))
    new_spent = spent + consumed
    if new_spent > limit:
        raise InvalidPrivacyBudget("insufficient privacy budget balance")
    release_id = _validate_release_id(payload.get("release_id"))
    secret = _decode_noise_secret(payload.get("noise_secret"))

    counts = [0] * len(partitions)
    sums = [[Decimal(0)] * len(metrics) for _ in partitions]
    position_of = {signature: index for index, (_key, signature) in enumerate(partitions)}
    with localcontext() as context:
        context.prec = 60
        for record in records:
            values = [_resolve(record, segments, InvalidGroupBy) for segments in group_pointers]
            signature = tuple(_group_signature_value(value) for value in values)
            position = position_of.get(signature)
            if position is None:
                # Records outside every public partition are ignored.
                continue
            counts[position] += 1
            for index, (_name, operation, segments, lower, upper, _eps) in enumerate(metrics):
                if operation != "sum":
                    continue
                value = _decimal_number(_resolve(record, segments, InvalidMetric))
                if value < lower:
                    value = lower
                elif value > upper:
                    value = upper
                sums[position][index] += value

    results: list[dict] = []
    for position, (key, signature) in enumerate(partitions):
        metric_values: dict[str, Any] = {}
        for index, (name, operation, _segments, lower, upper, _eps) in enumerate(metrics):
            epsilon = float(epsilons[index])
            if operation == "count":
                scale = 1.0 / epsilon
                noisy = counts[position] + _laplace_noise(
                    secret, release_id, signature, name, scale
                )
                if noisy < 0:
                    noisy = 0.0
            else:
                scale = float(upper - lower) / epsilon
                noisy = float(sums[position][index]) + _laplace_noise(
                    secret, release_id, signature, name, scale
                )
            metric_values[name] = _round6(Decimal(str(noisy)))
        results.append({"key": key, "metrics": metric_values})

    return {
        "partitions": results,
        "consumed": _round6(consumed),
        "spent": _round6(new_spent),
        "remaining": _round6(limit - new_spent),
    }
