"""Federated-learning update aggregation with per-update L2 clipping.

Pure and request-scoped like the other capabilities: participant updates
are only read from the current payload, the caller's data is never
mutated and nothing is retained between requests. Each update vector is
clipped in its entirety to ``max_l2_norm`` (zero vectors are left
untouched), then the clipped vectors are combined into one dimension-wise
weighted average using each participant's ``sample_count`` as weight.
Results never depend on update order, and nothing about an individual
update — its identifier, its vector or its sample count — is echoed back
in an error response.
"""

from __future__ import annotations

import math
from decimal import ROUND_HALF_UP, Decimal, localcontext
from typing import Any

from .classifier import InvalidRequest

_QUANTUM = Decimal("0.000001")

_MIN_PARTICIPANTS = 2
_MAX_PARTICIPANTS = 100
_MIN_SAMPLE_COUNT = 1
_MAX_SAMPLE_COUNT = 1_000_000
_MIN_DIMENSION = 1
_MAX_DIMENSION = 4096


class InvalidFederatedConfig(ValueError):
    """round_id, minimum_participants or max_l2_norm is malformed."""


class InvalidUpdate(ValueError):
    """A participant update entry or one of its fields is malformed."""


class InsufficientParticipants(ValueError):
    """Fewer updates than minimum_participants were supplied."""


def _round6(value: Decimal) -> float:
    """Round a decimal to six places, half up, normalizing negative zero."""
    quantized = value.quantize(_QUANTUM, rounding=ROUND_HALF_UP)
    if quantized == 0:
        return 0.0
    return float(quantized)


def _validate_round_id(raw: Any) -> str:
    if not isinstance(raw, str) or not raw:
        raise InvalidFederatedConfig("round_id must be a non-empty string")
    return raw


def _validate_minimum_participants(raw: Any) -> int:
    # bool is an int subclass in Python, but JSON true/false is not a number.
    if isinstance(raw, bool) or not isinstance(raw, int):
        raise InvalidFederatedConfig(
            "minimum_participants must be a JSON integer between 2 and 100"
        )
    if not _MIN_PARTICIPANTS <= raw <= _MAX_PARTICIPANTS:
        raise InvalidFederatedConfig(
            "minimum_participants must be a JSON integer between 2 and 100"
        )
    return raw


def _validate_max_l2_norm(raw: Any) -> Decimal:
    if isinstance(raw, bool) or not isinstance(raw, (int, float)):
        raise InvalidFederatedConfig("max_l2_norm must be a positive finite number")
    if isinstance(raw, float) and not math.isfinite(raw):
        raise InvalidFederatedConfig("max_l2_norm must be a positive finite number")
    value = Decimal(raw) if isinstance(raw, int) else Decimal(str(raw))
    if value <= 0:
        raise InvalidFederatedConfig("max_l2_norm must be a positive finite number")
    return value


def _validate_sample_count(raw: Any) -> int:
    if isinstance(raw, bool) or not isinstance(raw, int):
        raise InvalidUpdate("sample_count must be a JSON integer between 1 and 1000000")
    if not _MIN_SAMPLE_COUNT <= raw <= _MAX_SAMPLE_COUNT:
        raise InvalidUpdate("sample_count must be a JSON integer between 1 and 1000000")
    return raw


def _decimal_element(raw: Any) -> Decimal:
    if isinstance(raw, bool) or not isinstance(raw, (int, float)):
        raise InvalidUpdate("values must contain only finite JSON numbers")
    if isinstance(raw, float) and not math.isfinite(raw):
        raise InvalidUpdate("values must contain only finite JSON numbers")
    return Decimal(raw) if isinstance(raw, int) else Decimal(str(raw))


def _validate_values(raw: Any) -> list[Decimal]:
    if not isinstance(raw, list):
        raise InvalidUpdate("values must be a one-dimensional array")
    if not _MIN_DIMENSION <= len(raw) <= _MAX_DIMENSION:
        raise InvalidUpdate("values must contain between 1 and 4096 numbers")
    return [_decimal_element(element) for element in raw]


def _validate_update(raw: Any) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise InvalidUpdate("each update must be an object")
    for field in ("participant_id", "sample_count", "values"):
        if field not in raw:
            raise InvalidUpdate(f"update is missing {field}")
    participant_id = raw["participant_id"]
    if not isinstance(participant_id, str) or not participant_id:
        raise InvalidUpdate("participant_id must be a non-empty string")
    sample_count = _validate_sample_count(raw["sample_count"])
    values = _validate_values(raw["values"])
    return {
        "participant_id": participant_id,
        "sample_count": sample_count,
        "values": values,
    }


def federated_aggregate_request(payload: Any) -> dict:
    """Validate a /v1/federated/aggregate payload and run the aggregation."""
    if not isinstance(payload, dict):
        raise InvalidRequest("request body must be a JSON object")
    raw_updates = payload.get("updates")
    if not isinstance(raw_updates, list) or not raw_updates:
        raise InvalidRequest("updates must be a non-empty array")

    round_id = _validate_round_id(payload.get("round_id"))
    minimum_participants = _validate_minimum_participants(payload.get("minimum_participants"))
    max_l2_norm = _validate_max_l2_norm(payload.get("max_l2_norm"))

    updates: list[dict[str, Any]] = []
    seen_participants: set[str] = set()
    dimension: int | None = None
    for raw in raw_updates:
        update = _validate_update(raw)
        if update["participant_id"] in seen_participants:
            raise InvalidUpdate("participant_id must be unique within the request")
        seen_participants.add(update["participant_id"])
        if dimension is None:
            dimension = len(update["values"])
        elif len(update["values"]) != dimension:
            raise InvalidUpdate("all updates must have the same vector dimension")
        updates.append(update)
    assert dimension is not None

    if len(updates) < minimum_participants:
        # Nothing is published below the participant threshold.
        raise InsufficientParticipants("not enough participants to publish an aggregate")

    with localcontext() as context:
        context.prec = 60
        weighted_sums = [Decimal(0)] * dimension
        total_sample_count = 0
        clipped_participants: list[str] = []
        for update in updates:
            vector = update["values"]
            norm = sum((value * value for value in vector), Decimal(0)).sqrt()
            if norm > max_l2_norm:
                # Scale the whole vector by max_l2_norm / its original norm.
                factor = max_l2_norm / norm
                vector = [value * factor for value in vector]
                clipped_participants.append(update["participant_id"])
            weight = Decimal(update["sample_count"])
            total_sample_count += update["sample_count"]
            for index, value in enumerate(vector):
                weighted_sums[index] += weight * value
        denominator = Decimal(total_sample_count)
        aggregate = [_round6(total / denominator) for total in weighted_sums]

    return {
        "round_id": round_id,
        "participant_count": len(updates),
        "total_sample_count": total_sample_count,
        "dimension": dimension,
        "aggregate": aggregate,
        "clipped_participants": sorted(clipped_participants),
    }
