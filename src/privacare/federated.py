"""Federated-learning update aggregation.

Pure and request-scoped like the other capabilities: participant updates
are only read from the current payload, the caller's data is never
mutated and nothing is retained between requests. Each update vector is
clipped as a whole to ``max_l2_norm`` (zero vectors are left untouched),
then the clipped vectors are combined into a per-dimension weighted
average using each participant's ``sample_count``. Updates arriving below
``minimum_participants`` suppress the release entirely, so neither the
aggregate nor any clipping detail leaves the process.
"""

from __future__ import annotations

import math
from decimal import Decimal, localcontext
from typing import Any

from .aggregate import _decimal_number, _round6
from .classifier import InvalidRequest

_MIN_PARTICIPANTS = 2
_MAX_PARTICIPANTS = 100
_MIN_SAMPLE_COUNT = 1
_MAX_SAMPLE_COUNT = 1_000_000
_MIN_DIMENSION = 1
_MAX_DIMENSION = 4096


class InvalidFederatedConfig(ValueError):
    """round_id, minimum_participants or max_l2_norm is malformed."""


class InvalidUpdate(ValueError):
    """An update entry, participant, sample count or vector is malformed."""


class InsufficientParticipants(ValueError):
    """Fewer updates than minimum_participants were supplied."""


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
    value = _decimal_number(raw)
    if value <= 0:
        raise InvalidFederatedConfig("max_l2_norm must be a positive finite number")
    return value


def _validate_sample_count(raw: Any) -> int:
    if isinstance(raw, bool) or not isinstance(raw, int):
        raise InvalidUpdate("sample_count must be a JSON integer between 1 and 1000000")
    if not _MIN_SAMPLE_COUNT <= raw <= _MAX_SAMPLE_COUNT:
        raise InvalidUpdate("sample_count must be a JSON integer between 1 and 1000000")
    return raw


def _validate_vector(raw: Any, dimension: int | None) -> list[Decimal]:
    if not isinstance(raw, list):
        raise InvalidUpdate("values must be an array of finite JSON numbers")
    if not _MIN_DIMENSION <= len(raw) <= _MAX_DIMENSION:
        raise InvalidUpdate("values must contain between 1 and 4096 elements")
    if dimension is not None and len(raw) != dimension:
        raise InvalidUpdate("every update must have the same vector dimension")
    vector: list[Decimal] = []
    for element in raw:
        if isinstance(element, bool) or not isinstance(element, (int, float)):
            raise InvalidUpdate("values must contain only finite JSON numbers")
        if isinstance(element, float) and not math.isfinite(element):
            raise InvalidUpdate("values must contain only finite JSON numbers")
        vector.append(_decimal_number(element))
    return vector


def _validate_updates(raw: Any) -> list:
    """Array-level structure: updates must be a non-empty array."""
    if not isinstance(raw, list) or not raw:
        raise InvalidRequest("updates must be a non-empty array")
    return raw


def _parse_updates(raw: list) -> list[tuple[str, int, list[Decimal]]]:
    updates: list[tuple[str, int, list[Decimal]]] = []
    seen: set[str] = set()
    dimension: int | None = None
    for item in raw:
        if not isinstance(item, dict):
            raise InvalidUpdate("each update must be an object")
        for field in ("participant_id", "sample_count", "values"):
            if field not in item:
                raise InvalidUpdate(f"update is missing {field}")
        participant_id = item["participant_id"]
        if not isinstance(participant_id, str) or not participant_id:
            raise InvalidUpdate("participant_id must be a unique non-empty string")
        if participant_id in seen:
            raise InvalidUpdate("participant_id must be unique within the request")
        seen.add(participant_id)
        sample_count = _validate_sample_count(item["sample_count"])
        vector = _validate_vector(item["values"], dimension)
        dimension = len(vector)
        updates.append((participant_id, sample_count, vector))
    return updates


def federated_aggregate_request(payload: Any) -> dict:
    """Validate a /v1/federated/aggregate payload and run the aggregation."""
    if not isinstance(payload, dict):
        raise InvalidRequest("request body must be a JSON object")
    raw_updates = _validate_updates(payload.get("updates"))
    round_id = _validate_round_id(payload.get("round_id"))
    minimum_participants = _validate_minimum_participants(payload.get("minimum_participants"))
    max_l2_norm = _validate_max_l2_norm(payload.get("max_l2_norm"))
    updates = _parse_updates(raw_updates)

    participant_count = len(updates)
    if participant_count < minimum_participants:
        # Nothing is published until the participant threshold is met.
        raise InsufficientParticipants(
            "not enough participants to publish the aggregate"
        )

    dimension = len(updates[0][2])
    weighted_sums = [Decimal(0)] * dimension
    total_sample_count = 0
    clipped: list[str] = []
    with localcontext() as context:
        context.prec = 60
        for participant_id, sample_count, vector in updates:
            norm = Decimal(0)
            for value in vector:
                norm += value * value
            norm = norm.sqrt()
            if norm > max_l2_norm:
                # Scale the whole vector by bound / original norm; a zero
                # vector has norm zero and is therefore never scaled.
                factor = max_l2_norm / norm
                vector = [value * factor for value in vector]
                clipped.append(participant_id)
            total_sample_count += sample_count
            for index, value in enumerate(vector):
                weighted_sums[index] += Decimal(sample_count) * value
        denominator = Decimal(total_sample_count)
        aggregate = []
        for weighted_sum in weighted_sums:
            rounded = _round6(weighted_sum / denominator)
            if rounded == 0:
                # Canonicalise decimal negative zero to plain zero.
                rounded = 0.0
            aggregate.append(rounded)

    return {
        "round_id": round_id,
        "participant_count": participant_count,
        "total_sample_count": total_sample_count,
        "dimension": dimension,
        "aggregate": aggregate,
        "clipped_participants": sorted(clipped),
    }
