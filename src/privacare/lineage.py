"""Request-level data lineage tracing across dataset transfers.

Pure and request-scoped like the other modules: datasets, transfers and
queries are read from the current payload only, nothing is persisted
between requests, the caller's data is never mutated, and identical
inputs always produce identical results. A trace only follows a transfer
whose categories cover every queried category and whose ``occurred_at``
is not later than the query's ``as_of``; reachability is measured by the
shortest edge count with the lexicographically smallest transfer_id
sequence breaking ties.
"""

from __future__ import annotations

import heapq
import re
from datetime import datetime
from typing import Any

from .classifier import CATEGORIES, InvalidRequest

DIRECTIONS: tuple[str, ...] = ("upstream", "downstream")

_CATEGORY_SET = frozenset(CATEGORIES)
_DIRECTION_SET = frozenset(DIRECTIONS)

# RFC 3339 date-time with a mandatory numeric offset or "Z".
_RFC3339_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$"
)

_DATASET_FIELDS = ("dataset_id", "data_categories")
_TRANSFER_FIELDS = (
    "transfer_id",
    "from_dataset",
    "to_dataset",
    "occurred_at",
    "data_categories",
)
_QUERY_FIELDS = ("dataset_id", "direction", "data_categories", "max_depth")


class InvalidDataset(ValueError):
    """A dataset entry is malformed."""


class InvalidTransfer(ValueError):
    """A transfer entry is malformed."""


class InvalidQuery(ValueError):
    """A lineage query entry is malformed."""


def _parse_timestamp(raw: Any, error: type[ValueError], field: str) -> datetime:
    """Parse an RFC 3339 timestamp that must carry a timezone offset."""
    if not isinstance(raw, str) or not _RFC3339_RE.match(raw):
        raise error(f"{field} must be an RFC 3339 date-time with a timezone offset")
    text = raw[:-1] + "+00:00" if raw.endswith("Z") else raw
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        raise error(f"{field} must be a valid RFC 3339 date-time") from None


def _require_id(entry: dict, field: str, error: type[ValueError]) -> str:
    value = entry.get(field)
    if not isinstance(value, str) or not value:
        raise error(f"{field} must be a non-empty string")
    return value


def _require_categories(entry: dict, error: type[ValueError]) -> list[str]:
    """Validate a non-empty, duplicate-free category list limited to five."""
    value = entry.get("data_categories")
    if not isinstance(value, list) or not value:
        raise error("data_categories must be a non-empty array")
    cats: list[str] = []
    seen: set[str] = set()
    for item in value:
        if not isinstance(item, str) or not item:
            raise error("data_categories must contain only non-empty strings")
        if item not in _CATEGORY_SET:
            raise error("data_categories contains an unsupported category")
        if item in seen:
            raise error("data_categories must not contain duplicates")
        seen.add(item)
        cats.append(item)
    return cats


def _parse_dataset(raw: Any) -> dict:
    if not isinstance(raw, dict):
        raise InvalidDataset("each dataset must be an object")
    for field in _DATASET_FIELDS:
        if field not in raw:
            raise InvalidDataset(f"dataset is missing {field}")
    dataset_id = _require_id(raw, "dataset_id", InvalidDataset)
    cats = _require_categories(raw, InvalidDataset)
    return {"dataset_id": dataset_id, "data_categories": frozenset(cats)}


def _parse_transfer(raw: Any, dataset_ids: set[str], dataset_cats: dict[str, frozenset[str]]) -> dict:
    if not isinstance(raw, dict):
        raise InvalidTransfer("each transfer must be an object")
    for field in _TRANSFER_FIELDS:
        if field not in raw:
            raise InvalidTransfer(f"transfer is missing {field}")
    transfer_id = _require_id(raw, "transfer_id", InvalidTransfer)
    from_dataset = _require_id(raw, "from_dataset", InvalidTransfer)
    to_dataset = _require_id(raw, "to_dataset", InvalidTransfer)
    if from_dataset not in dataset_ids:
        raise InvalidTransfer("from_dataset must reference a known dataset")
    if to_dataset not in dataset_ids:
        raise InvalidTransfer("to_dataset must reference a known dataset")
    if from_dataset == to_dataset:
        raise InvalidTransfer("from_dataset and to_dataset must be different datasets")
    occurred_at = _parse_timestamp(raw["occurred_at"], InvalidTransfer, "occurred_at")
    cats = frozenset(_require_categories(raw, InvalidTransfer))
    if not cats <= dataset_cats[from_dataset]:
        raise InvalidTransfer("transfer data_categories must be a subset of from_dataset categories")
    if not cats <= dataset_cats[to_dataset]:
        raise InvalidTransfer("transfer data_categories must be a subset of to_dataset categories")
    return {
        "transfer_id": transfer_id,
        "from_dataset": from_dataset,
        "to_dataset": to_dataset,
        "occurred_at": occurred_at,
        "data_categories": cats,
    }


def _parse_query(raw: Any, dataset_ids: set[str], dataset_cats: dict[str, frozenset[str]]) -> dict:
    if not isinstance(raw, dict):
        raise InvalidQuery("each query must be an object")
    for field in _QUERY_FIELDS:
        if field not in raw:
            raise InvalidQuery(f"query is missing {field}")
    dataset_id = _require_id(raw, "dataset_id", InvalidQuery)
    if dataset_id not in dataset_ids:
        raise InvalidQuery("dataset_id must reference a known dataset")
    direction = raw["direction"]
    if not isinstance(direction, str) or direction not in _DIRECTION_SET:
        raise InvalidQuery("direction must be 'upstream' or 'downstream'")
    cats = frozenset(_require_categories(raw, InvalidQuery))
    if not cats <= dataset_cats[dataset_id]:
        raise InvalidQuery(
            "query data_categories must be a subset of the start dataset categories"
        )
    max_depth = raw["max_depth"]
    # bool is an int subclass in Python, but JSON true/false is not an integer.
    if isinstance(max_depth, bool) or not isinstance(max_depth, int) or not 1 <= max_depth <= 20:
        raise InvalidQuery("max_depth must be a JSON integer between 1 and 20")
    as_of = None
    if "as_of" in raw and raw["as_of"] is not None:
        as_of = _parse_timestamp(raw["as_of"], InvalidQuery, "as_of")
    return {
        "dataset_id": dataset_id,
        "direction": direction,
        "data_categories": cats,
        "max_depth": max_depth,
        "as_of": as_of,
    }


def _trace_one(query: dict, transfers: list[dict]) -> list[dict]:
    """Shortest paths from the start dataset, filtering usable edges.

    A transfer is usable when it carries every queried category and its
    occurrence time is not later than ``as_of`` (if given). Edges are
    then traversed in the queried direction. Distance is the edge count;
    among equal-length paths the lexicographically smallest transfer_id
    sequence wins, computed with a Dijkstra-style search over
    (distance, path) labels.
    """
    wanted = query["data_categories"]
    as_of = query["as_of"]
    downstream = query["direction"] == "downstream"

    adjacency: dict[str, list[tuple[str, str]]] = {}
    for transfer in transfers:
        if not wanted <= transfer["data_categories"]:
            continue
        if as_of is not None and transfer["occurred_at"] > as_of:
            continue
        if downstream:
            src, dst = transfer["from_dataset"], transfer["to_dataset"]
        else:
            src, dst = transfer["to_dataset"], transfer["from_dataset"]
        adjacency.setdefault(src, []).append((dst, transfer["transfer_id"]))

    start = query["dataset_id"]
    # Best label per node: (distance, transfer_id path). Empty tuple sorts
    # before any edge path, anchoring the start at distance 0.
    best: dict[str, tuple[int, tuple[str, ...]]] = {start: (0, ())}
    # Heap entries: (distance, path_tuple, node). Path is the ordered
    # transfer_id list from the start to node.
    heap: list[tuple[int, tuple[str, ...], str]] = [(0, (), start)]
    while heap:
        dist, path, node = heapq.heappop(heap)
        if best.get(node) != (dist, path):
            continue
        if dist >= query["max_depth"]:
            continue
        for nxt, transfer_id in adjacency.get(node, ()):
            candidate = (dist + 1, path + (transfer_id,))
            current = best.get(nxt)
            if current is None or candidate < current:
                best[nxt] = candidate
                heapq.heappush(heap, (candidate[0], candidate[1], nxt))

    entries = [
        {
            "dataset_id": start,
            "distance": 0,
            "transfer_path": [],
        }
    ]
    for dataset_id, (dist, path) in best.items():
        if dataset_id == start:
            continue
        entries.append(
            {
                "dataset_id": dataset_id,
                "distance": dist,
                "transfer_path": list(path),
            }
        )
    entries.sort(key=lambda entry: (entry["distance"], entry["dataset_id"]))
    return entries


def trace_lineage(payload: Any) -> dict:
    """Validate a /v1/lineage/trace payload and answer every query."""
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
    dataset_ids: set[str] = set()
    dataset_cats: dict[str, frozenset[str]] = {}
    for dataset in datasets:
        dataset_id = dataset["dataset_id"]
        if dataset_id in dataset_ids:
            raise InvalidDataset("dataset_id must be unique within the request")
        dataset_ids.add(dataset_id)
        dataset_cats[dataset_id] = dataset["data_categories"]

    transfers = [
        _parse_transfer(raw, dataset_ids, dataset_cats) for raw in raw_transfers
    ]
    seen_transfer_ids: set[str] = set()
    for transfer in transfers:
        transfer_id = transfer["transfer_id"]
        if transfer_id in seen_transfer_ids:
            raise InvalidTransfer("transfer_id must be unique within the request")
        seen_transfer_ids.add(transfer_id)

    queries = [_parse_query(raw, dataset_ids, dataset_cats) for raw in raw_queries]

    results = [
        {
            "index": index,
            "dataset_id": query["dataset_id"],
            "direction": query["direction"],
            "datasets": _trace_one(query, transfers),
        }
        for index, query in enumerate(queries)
    ]
    return {"results": results}
