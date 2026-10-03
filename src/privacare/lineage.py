"""Request-level data lineage tracing across datasets.

Pure and request-scoped like the other modules: datasets, transfers and
queries are read from the current payload only, nothing is persisted
between requests, the caller's data is never mutated, and identical
inputs always produce identical results. Tracing is a bounded shortest
edge traversal over a time- and category-filtered transfer graph; the
query categories must be carried by every edge on the path, and edges
later than a query's ``as_of`` are ignored.
"""

from __future__ import annotations

import re
from collections import deque
from datetime import datetime
from typing import Any

from .classifier import CATEGORIES, InvalidRequest

_CATEGORY_SET = frozenset(CATEGORIES)

# RFC 3339 date-time with a mandatory numeric offset or "Z".
_RFC3339_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$"
)

_MIN_DEPTH = 1
_MAX_DEPTH = 20


class InvalidDataset(ValueError):
    """A dataset entry is malformed."""


class InvalidTransfer(ValueError):
    """A transfer entry is malformed or references unknown datasets."""


class InvalidQuery(ValueError):
    """A trace query is malformed."""


def _parse_time(raw: Any, error: type[ValueError]) -> datetime:
    """Parse an RFC 3339 timestamp that must carry a timezone offset."""
    if not isinstance(raw, str) or not _RFC3339_RE.match(raw):
        raise error("timestamps must be RFC 3339 date-times with a timezone offset")
    text = raw[:-1] + "+00:00" if raw.endswith("Z") else raw
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        raise error("timestamps must be valid RFC 3339 date-times") from None


def _require_id(entry: Any, field: str, error: type[ValueError]) -> str:
    if not isinstance(entry, dict) or not isinstance(entry.get(field), str) or not entry[field]:
        raise error(f"{field} must be a non-empty string")
    return entry[field]


def _require_categories(
    entry: dict, field: str, error: type[ValueError]
) -> frozenset[str]:
    value = entry.get(field)
    if not isinstance(value, list) or not value:
        raise error(f"{field} must be a non-empty array")
    seen: set[str] = set()
    for item in value:
        if not isinstance(item, str) or not item:
            raise error(f"{field} must contain only non-empty strings")
        if item in seen:
            raise error(f"{field} must not contain duplicates")
        seen.add(item)
    if not seen <= _CATEGORY_SET:
        raise error(f"{field} contains an unsupported category")
    return frozenset(value)


def _parse_dataset(raw: Any) -> dict:
    if not isinstance(raw, dict):
        raise InvalidDataset("each dataset must be an object")
    dataset_id = _require_id(raw, "dataset_id", InvalidDataset)
    categories = _require_categories(raw, "data_categories", InvalidDataset)
    return {"dataset_id": dataset_id, "data_categories": categories}


def _parse_transfer(raw: Any) -> dict:
    if not isinstance(raw, dict):
        raise InvalidTransfer("each transfer must be an object")
    transfer_id = _require_id(raw, "transfer_id", InvalidTransfer)
    from_dataset = _require_id(raw, "from_dataset", InvalidTransfer)
    to_dataset = _require_id(raw, "to_dataset", InvalidTransfer)
    if from_dataset == to_dataset:
        raise InvalidTransfer("from_dataset and to_dataset must be different datasets")
    categories = _require_categories(raw, "data_categories", InvalidTransfer)
    occurred_at = _parse_time(raw.get("occurred_at"), InvalidTransfer)
    return {
        "transfer_id": transfer_id,
        "from_dataset": from_dataset,
        "to_dataset": to_dataset,
        "data_categories": categories,
        "occurred_at": occurred_at,
    }


def _parse_depth(raw: Any) -> int:
    # bool is an int subclass in Python, but JSON true/false is not a number.
    if isinstance(raw, bool) or not isinstance(raw, int) or not _MIN_DEPTH <= raw <= _MAX_DEPTH:
        raise InvalidQuery(f"max_depth must be a JSON integer between {_MIN_DEPTH} and {_MAX_DEPTH}")
    return raw


def _parse_query(raw: Any, dataset_categories: dict[str, frozenset[str]]) -> dict:
    if not isinstance(raw, dict):
        raise InvalidQuery("each query must be an object")
    for field in ("dataset_id", "direction", "data_categories", "max_depth"):
        if field not in raw:
            raise InvalidQuery(f"query is missing {field}")
    dataset_id = _require_id(raw, "dataset_id", InvalidQuery)
    if dataset_id not in dataset_categories:
        raise InvalidQuery("dataset_id must reference a dataset in the request")
    direction = raw["direction"]
    if direction not in ("upstream", "downstream"):
        raise InvalidQuery("direction must be 'upstream' or 'downstream'")
    categories = _require_categories(raw, "data_categories", InvalidQuery)
    if not categories <= dataset_categories[dataset_id]:
        raise InvalidQuery("data_categories must be a subset of the start dataset categories")
    max_depth = _parse_depth(raw["max_depth"])
    as_of = None
    if "as_of" in raw:
        as_of = _parse_time(raw["as_of"], InvalidQuery)
    return {
        "dataset_id": dataset_id,
        "direction": direction,
        "data_categories": categories,
        "max_depth": max_depth,
        "as_of": as_of,
    }


def _trace_one(query: dict, adjacency: dict[str, list[dict]]) -> list[dict]:
    """BFS over the filtered graph, keeping the lexicographically smallest
    transfer_id sequence among all shortest paths to each dataset."""
    start = query["dataset_id"]
    wanted = query["data_categories"]
    as_of = query["as_of"]

    def usable(transfer: dict) -> bool:
        return wanted <= transfer["data_categories"] and (
            as_of is None or transfer["occurred_at"] <= as_of
        )

    # distance / path of the lexicographically smallest shortest route.
    distances = {start: 0}
    paths = {start: ()}
    queue = deque([(start, 0)])
    while queue:
        current, depth = queue.popleft()
        if depth >= query["max_depth"]:
            continue
        for transfer in adjacency.get(current, ()):
            if not usable(transfer):
                continue
            nxt = transfer["to_dataset"]
            candidate_path = paths[current] + (transfer["transfer_id"],)
            known = nxt in distances
            better = (
                not known
                or depth + 1 < distances[nxt]
                or (depth + 1 == distances[nxt] and candidate_path < paths[nxt])
            )
            if better:
                distances[nxt] = depth + 1
                paths[nxt] = candidate_path
                if not known:
                    queue.append((nxt, depth + 1))

    return [
        {"dataset_id": dataset_id, "distance": distances[dataset_id], "transfer_path": list(paths[dataset_id])}
        for dataset_id in sorted(distances, key=lambda item: (distances[item], item))
    ]


def trace_lineage_request(payload: Any) -> dict:
    """Validate a /v1/lineage/trace payload and trace every query."""
    if not isinstance(payload, dict):
        raise InvalidRequest("request body must be a JSON object")
    raw_datasets = payload.get("datasets")
    if not isinstance(raw_datasets, list) or not raw_datasets:
        raise InvalidRequest("datasets must be a non-empty array")
    raw_transfers = payload.get("transfers")
    if not isinstance(raw_transfers, list):
        raise InvalidRequest("transfers must be an array")
    raw_queries = payload.get("queries")
    if not isinstance(raw_queries, list) or not raw_queries:
        raise InvalidRequest("queries must be a non-empty array")

    datasets = [_parse_dataset(raw) for raw in raw_datasets]
    dataset_categories: dict[str, frozenset[str]] = {}
    for dataset in datasets:
        dataset_id = dataset["dataset_id"]
        if dataset_id in dataset_categories:
            raise InvalidDataset("dataset_id must be unique within the request")
        dataset_categories[dataset_id] = dataset["data_categories"]
    dataset_ids = frozenset(dataset_categories)

    transfers = [_parse_transfer(raw) for raw in raw_transfers]
    seen_transfer_ids: set[str] = set()
    downstream: dict[str, list[dict]] = {}
    upstream: dict[str, list[dict]] = {}
    for transfer in transfers:
        transfer_id = transfer["transfer_id"]
        if transfer_id in seen_transfer_ids:
            raise InvalidTransfer("transfer_id must be unique within the request")
        seen_transfer_ids.add(transfer_id)
        if transfer["from_dataset"] not in dataset_ids:
            raise InvalidTransfer("from_dataset must reference a dataset in the request")
        if transfer["to_dataset"] not in dataset_ids:
            raise InvalidTransfer("to_dataset must reference a dataset in the request")
        from_categories = dataset_categories[transfer["from_dataset"]]
        to_categories = dataset_categories[transfer["to_dataset"]]
        if not transfer["data_categories"] <= from_categories:
            raise InvalidTransfer(
                "data_categories must be a subset of the from_dataset categories"
            )
        if not transfer["data_categories"] <= to_categories:
            raise InvalidTransfer(
                "data_categories must be a subset of the to_dataset categories"
            )
        downstream.setdefault(transfer["from_dataset"], []).append(transfer)
        upstream.setdefault(transfer["to_dataset"], []).append(
            {**transfer, "to_dataset": transfer["from_dataset"]}
        )

    queries = [_parse_query(raw, dataset_categories) for raw in raw_queries]

    results = []
    for index, query in enumerate(queries):
        adjacency = downstream if query["direction"] == "downstream" else upstream
        results.append(
            {
                "index": index,
                "dataset_id": query["dataset_id"],
                "direction": query["direction"],
                "datasets": _trace_one(query, adjacency),
            }
        )
    return {"results": results}
