"""Policy-driven de-identification of medical records.

Reuses the classifier's leaf detection so a /v1/deidentify request flags
exactly the same fields as /v1/classify would for the same records and
schema; the policy then decides what happens to each flagged leaf. All
logic is pure and request-scoped, and input records are never mutated.
"""

from __future__ import annotations

import copy
from typing import Any

from .classifier import (
    CATEGORIES,
    InvalidRequest,
    InvalidSchema,
    _collect_hits,
    _parse_pointer,
    _parse_records_and_schema,
)

__all__ = ["InvalidPolicy", "deidentify_request"]

_ACTIONS: tuple[str, ...] = ("keep", "redact", "drop")

# When a leaf hits several categories, the strictest configured action wins.
_ACTION_PRIORITY: tuple[str, ...] = ("drop", "redact", "keep")

_CATEGORY_SET = frozenset(CATEGORIES)


class InvalidPolicy(ValueError):
    """The caller-supplied de-identification policy is malformed."""


def _parse_policy(payload: dict) -> dict[str, str]:
    if "policy" not in payload:
        raise InvalidRequest("policy is required")
    policy = payload["policy"]
    if not isinstance(policy, dict) or not policy:
        raise InvalidPolicy("policy must be a non-empty object")
    actions: dict[str, str] = {}
    for category, action in policy.items():
        if category not in _CATEGORY_SET:
            raise InvalidPolicy("policy contains an unsupported category")
        if not isinstance(action, str) or action not in _ACTIONS:
            raise InvalidPolicy("policy actions must be 'keep', 'redact' or 'drop'")
        actions[category] = action
    return actions


def _select_action(cats: set[str], policy: dict[str, str]) -> str:
    for action in _ACTION_PRIORITY:
        if any(policy.get(cat, "keep") == action for cat in cats):
            return action
    return "keep"


def _apply(record: dict, segments: tuple[str, ...], action: str) -> None:
    parent: Any = record
    for segment in segments[:-1]:
        parent = parent[int(segment)] if isinstance(parent, list) else parent[segment]
    last = segments[-1]
    if action == "drop" and isinstance(parent, dict):
        del parent[last]
    elif isinstance(parent, list):
        parent[int(last)] = None
    else:
        parent[last] = None


def _deidentify_record(record: dict, rules: list, policy: dict[str, str]) -> tuple[dict, list[dict]]:
    hits = _collect_hits(record, rules)
    transformed = copy.deepcopy(record)
    transformations = []
    for path in sorted(hits):
        cats, _sources = hits[path]
        action = _select_action(cats, policy)
        if action == "keep":
            continue
        _apply(transformed, _parse_pointer(path), action)
        transformations.append(
            {
                "path": path,
                "action": action,
                "categories": [c for c in CATEGORIES if c in cats],
            }
        )
    return transformed, transformations


def deidentify_request(payload: Any) -> list[dict]:
    """Validate a /v1/deidentify payload and de-identify every record."""
    records, rules = _parse_records_and_schema(payload)
    policy = _parse_policy(payload)
    results = []
    for index, record in enumerate(records):
        transformed, transformations = _deidentify_record(record, rules, policy)
        results.append(
            {"index": index, "record": transformed, "transformations": transformations}
        )
    return results
