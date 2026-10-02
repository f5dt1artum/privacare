"""Policy-driven de-identification for medical records.

Built on the classifier: leaves are found with the exact same rules and the
request-scoped schema, then each record is deep-copied and transformed. The
module is pure and request-scoped — caller data is never mutated and nothing
leaks across requests.
"""

from __future__ import annotations

import copy
from typing import Any

from .classifier import (
    CATEGORIES,
    InvalidRequest,
    _parse_rules,
    _pointer,
    _record_hits,
    _validate_records,
)

ACTIONS: tuple[str, ...] = ("keep", "redact", "drop")

_CATEGORY_SET = frozenset(CATEGORIES)
_ACTION_SET = frozenset(ACTIONS)

# When a leaf hits several categories, the strictest configured action wins.
_ACTION_PRIORITY = {"drop": 0, "redact": 1, "keep": 2}


class InvalidPolicy(ValueError):
    """The caller-supplied de-identification policy is malformed."""


def _parse_policy(raw: Any) -> dict[str, str]:
    if not isinstance(raw, dict) or not raw:
        raise InvalidPolicy("policy must be a non-empty object")
    policy: dict[str, str] = {}
    for category, action in raw.items():
        if category not in _CATEGORY_SET:
            raise InvalidPolicy("policy contains an unknown category")
        if not isinstance(action, str) or action not in _ACTION_SET:
            raise InvalidPolicy("policy actions must be 'keep', 'redact' or 'drop'")
        policy[category] = action
    return policy


def _apply_action(node: Any, segments: tuple[str, ...], action: str) -> None:
    """Apply one transformation in place on the copied record."""
    for segment in segments[:-1]:
        node = node[int(segment)] if isinstance(node, list) else node[segment]
    last = segments[-1]
    if isinstance(node, list):
        # Array elements are never removed (indices must stay stable); both
        # redact and drop blank them out.
        node[int(last)] = None
    elif action == "drop":
        del node[last]
    else:
        node[last] = None


def _deidentify_record(record: dict, rules: list, policy: dict[str, str]) -> tuple[dict, list[dict]]:
    hits = _record_hits(record, rules)
    transformed = copy.deepcopy(record)
    transformations = []
    for segments, (cats, _sources) in hits.items():
        action = min(
            (policy.get(category, "keep") for category in cats),
            key=lambda a: _ACTION_PRIORITY[a],
        )
        if action == "keep":
            continue
        transformations.append(
            {
                "path": _pointer(segments),
                "action": action,
                "categories": [c for c in CATEGORIES if c in cats],
            }
        )
        _apply_action(transformed, segments, action)
    transformations.sort(key=lambda item: item["path"])
    return transformed, transformations


def deidentify_request(payload: Any) -> list[dict]:
    """Validate a /v1/deidentify payload and de-identify every record."""
    records = _validate_records(payload)
    if "policy" not in payload:
        raise InvalidRequest("policy is required")
    rules = _parse_rules(payload.get("schema"))
    policy = _parse_policy(payload["policy"])
    results = []
    for index, record in enumerate(records):
        transformed, transformations = _deidentify_record(record, rules, policy)
        results.append(
            {"index": index, "record": transformed, "transformations": transformations}
        )
    return results
