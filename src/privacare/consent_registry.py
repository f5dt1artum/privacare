"""进程内同意登记与用途约束评估。

本模块是显式 opt-in 的有状态能力:只有直接实例化并使用
:class:`ConsentRegistry` 的调用方才受这些规则约束,现有请求级 HTTP
接口(如 /v1/consent/evaluate)不受影响,也不要求现有调用方启用
同意检查。

注册表按 consent_id 保存同意记录的完整版本历史:相同内容的重复登记
幂等,内容变化或撤销产生递增版本,历史永不改写。评估入口针对单个
主体、单个用途、所需数据类别集合与评估时间给出确定的 ALLOW/DENY
结论与唯一原因码。快照导出为确定性 JSON,可完整恢复记录、版本与
撤销时间;导入要么整体成功要么保持原状。
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any

__all__ = [
    "ConsentRegistry",
    "ConsentNotFoundError",
    "InvalidConsentError",
    "InvalidConsentSnapshotError",
]

SNAPSHOT_FORMAT = "privacare.consent_registry.snapshot"
SNAPSHOT_VERSION = 1

ACTIVE = "active"
REVOKED = "revoked"

ALLOW = "ALLOW"
DENY = "DENY"

# 评估原因码。ALLOWED 之外均为拒绝原因,拒绝时按
# NO_CONSENT -> NOT_YET_EFFECTIVE -> REVOKED -> EXPIRED ->
# PURPOSE_NOT_ALLOWED -> DATA_CATEGORY_NOT_ALLOWED 的优先级返回唯一码。
REASON_ALLOWED = "ALLOWED"
REASON_NO_CONSENT = "NO_CONSENT"
REASON_NOT_YET_EFFECTIVE = "NOT_YET_EFFECTIVE"
REASON_REVOKED = "REVOKED"
REASON_EXPIRED = "EXPIRED"
REASON_PURPOSE_NOT_ALLOWED = "PURPOSE_NOT_ALLOWED"
REASON_DATA_CATEGORY_NOT_ALLOWED = "DATA_CATEGORY_NOT_ALLOWED"

# 登记/更新接受的字段,按位置参数顺序排列。
_RECORD_FIELDS = (
    "consent_id",
    "subject_id",
    "purposes",
    "data_categories",
    "valid_from",
    "valid_until",
)

_EVALUATE_FIELDS = ("subject_id", "purpose", "data_categories", "evaluated_at")

_REVOKE_FIELDS = ("consent_id", "revoked_at")


class InvalidConsentError(ValueError):
    """同意记录、撤销或评估请求的字段或取值非法。"""


class ConsentNotFoundError(LookupError):
    """查询、更新或撤销了不存在的 consent_id。"""


class InvalidConsentSnapshotError(ValueError):
    """同意快照的格式、版本或记录关系非法。"""


def _parse_instant(value: Any, field: str, error: type[ValueError]) -> datetime:
    """解析带时区的 ISO 8601 时间;接受 datetime 或字符串,必须带时区。"""
    if isinstance(value, datetime):
        instant = value
    elif isinstance(value, str):
        text = value.strip()
        if text.endswith(("Z", "z")):
            text = text[:-1] + "+00:00"
        try:
            instant = datetime.fromisoformat(text)
        except ValueError:
            raise error(f"{field} must be a valid ISO 8601 date-time") from None
    else:
        raise error(f"{field} must be an ISO 8601 date-time string or datetime")
    if instant.tzinfo is None or instant.tzinfo.utcoffset(instant) is None:
        raise error(f"{field} must carry a timezone offset")
    return instant


def _parse_identifier(value: Any, field: str, error: type[ValueError]) -> str:
    if not isinstance(value, str) or not value:
        raise error(f"{field} must be a non-empty string")
    return value


def _parse_string_set(value: Any, field: str, error: type[ValueError]) -> frozenset[str]:
    if isinstance(value, (str, bytes)) or not isinstance(value, (list, tuple, set, frozenset)):
        raise error(f"{field} must be a non-empty collection of strings")
    items: set[str] = set()
    for item in value:
        if not isinstance(item, str) or not item:
            raise error(f"{field} must contain only non-empty strings")
        items.add(item)
    if not items:
        raise error(f"{field} must not be empty")
    return frozenset(items)


def _collect_fields(
    args: tuple, kwargs: dict, names: tuple[str, ...], error: type[ValueError]
) -> dict:
    """支持 mapping、位置参数或关键字参数三种调用方式。"""
    if len(args) == 1 and isinstance(args[0], dict) and not kwargs:
        return dict(args[0])
    if len(args) > len(names):
        raise error(f"expected at most {len(names)} positional arguments")
    fields = dict(kwargs)
    for name, value in zip(names, args):
        if name in fields:
            raise error(f"{name} was given twice")
        fields[name] = value
    return fields


def _require(fields: dict, name: str, error: type[ValueError]) -> Any:
    if name not in fields:
        raise error(f"{name} is required")
    return fields[name]


def _format_instant(instant: datetime) -> str:
    return instant.isoformat()


class ConsentRegistry:
    """同意登记、版本化历史、撤销与用途约束评估的进程内注册表。"""

    def __init__(self) -> None:
        # consent_id -> 按版本升序排列的记录列表,历史只增不改。
        self._consents: dict[str, list[dict]] = {}

    # ------------------------------------------------------------------
    # 登记、更新、撤销、查询
    # ------------------------------------------------------------------

    def register(self, *args: Any, **kwargs: Any) -> dict:
        """登记一条同意。

        相同 consent_id 且内容相同的重复登记幂等,直接返回现有记录;
        内容变化时产生递增版本并保留历史;已撤销的同意重新登记会产生
        一个恢复为 active 的新版本。
        """
        record = self._build_record(_collect_fields(args, kwargs, _RECORD_FIELDS, InvalidConsentError))
        return self._commit(record, must_exist=False)

    def update(self, *args: Any, **kwargs: Any) -> dict:
        """更新一条已存在的同意;语义与登记一致,但 consent_id 必须已存在。"""
        record = self._build_record(_collect_fields(args, kwargs, _RECORD_FIELDS, InvalidConsentError))
        return self._commit(record, must_exist=True)

    def revoke(self, *args: Any, **kwargs: Any) -> dict:
        """撤销一条同意:产生一个 status 为 revoked 的新版本,不改写历史。

        撤销从 revoked_at 起生效;revoked_at 不得早于该记录的生效时间。
        以相同 revoked_at 重复撤销幂等。
        """
        fields = _collect_fields(args, kwargs, _REVOKE_FIELDS, InvalidConsentError)
        consent_id = _parse_identifier(fields.get("consent_id"), "consent_id", InvalidConsentError)
        revoked_at = _parse_instant(
            _require(fields, "revoked_at", InvalidConsentError), "revoked_at", InvalidConsentError
        )
        versions = self._consents.get(consent_id)
        if versions is None:
            raise ConsentNotFoundError(f"unknown consent_id: {consent_id}")
        latest = versions[-1]
        if revoked_at < latest["valid_from"]:
            raise InvalidConsentError("revoked_at must not be earlier than valid_from")
        if latest["status"] == REVOKED:
            if latest["revoked_at"] == revoked_at:
                return _public_record(latest)
            raise InvalidConsentError("consent is already revoked")
        record = dict(latest)
        record["version"] = latest["version"] + 1
        record["status"] = REVOKED
        record["revoked_at"] = revoked_at
        versions.append(record)
        return _public_record(record)

    def query(self, consent_id: str) -> dict:
        """返回某条同意的最新版本;不存在时抛出 ConsentNotFoundError。"""
        return _public_record(self._versions(consent_id)[-1])

    def get(self, consent_id: str) -> dict:
        """query 的别名。"""
        return self.query(consent_id)

    def history(self, consent_id: str) -> tuple[dict, ...]:
        """按版本升序返回某条同意的全部历史;返回值与内部状态隔离。"""
        return tuple(_public_record(v) for v in self._versions(consent_id))

    def __contains__(self, consent_id: object) -> bool:
        return isinstance(consent_id, str) and consent_id in self._consents

    def __len__(self) -> int:
        return len(self._consents)

    def consent_ids(self) -> tuple[str, ...]:
        """按字典序返回当前全部 consent_id。"""
        return tuple(sorted(self._consents))

    # ------------------------------------------------------------------
    # 评估
    # ------------------------------------------------------------------

    def evaluate(self, *args: Any, **kwargs: Any) -> dict:
        """评估某主体在指定时间是否允许一次使用。

        提交数据主体、单个用途、所需数据类别集合与评估时间,返回
        {"decision", "reason", "consent_id", "version"};未允许时
        consent_id 与 version 为 None。
        """
        fields = _collect_fields(args, kwargs, _EVALUATE_FIELDS, InvalidConsentError)
        subject_id = _parse_identifier(fields.get("subject_id"), "subject_id", InvalidConsentError)
        purpose = _parse_identifier(fields.get("purpose"), "purpose", InvalidConsentError)
        required = _parse_string_set(
            _require(fields, "data_categories", InvalidConsentError),
            "data_categories",
            InvalidConsentError,
        )
        moment = _parse_instant(
            _require(fields, "evaluated_at", InvalidConsentError), "evaluated_at", InvalidConsentError
        )

        latest_records = [
            versions[-1]
            for versions in self._consents.values()
            if versions[-1]["subject_id"] == subject_id
        ]
        if not latest_records:
            return _deny(REASON_NO_CONSENT)
        effective = [r for r in latest_records if r["valid_from"] <= moment]
        if not effective:
            return _deny(REASON_NOT_YET_EFFECTIVE)

        allowing = [
            r
            for r in effective
            if _active_at(r, moment)
            and not _expired_at(r, moment)
            and purpose in r["purposes"]
            and required <= r["data_categories"]
        ]
        if allowing:
            # 多条同时允许时取生效时间最晚者,再取 consent_id 字典序最小者。
            allowing.sort(key=lambda r: r["consent_id"])
            allowing.sort(key=lambda r: r["valid_from"], reverse=True)
            best = allowing[0]
            return {
                "decision": ALLOW,
                "reason": REASON_ALLOWED,
                "consent_id": best["consent_id"],
                "version": best["version"],
            }

        if any(not _active_at(r, moment) for r in effective):
            return _deny(REASON_REVOKED)
        if any(_expired_at(r, moment) for r in effective):
            return _deny(REASON_EXPIRED)
        if not any(purpose in r["purposes"] for r in effective):
            return _deny(REASON_PURPOSE_NOT_ALLOWED)
        return _deny(REASON_DATA_CATEGORY_NOT_ALLOWED)

    # ------------------------------------------------------------------
    # 快照
    # ------------------------------------------------------------------

    def export_snapshot(self) -> str:
        """导出确定性 JSON 快照;相同状态重复导出的字节一致。"""
        consents = []
        for consent_id in sorted(self._consents):
            versions = [
                {
                    "version": v["version"],
                    "subject_id": v["subject_id"],
                    "purposes": sorted(v["purposes"]),
                    "data_categories": sorted(v["data_categories"]),
                    "valid_from": _format_instant(v["valid_from"]),
                    "valid_until": (
                        _format_instant(v["valid_until"]) if v["valid_until"] is not None else None
                    ),
                    "status": v["status"],
                    "revoked_at": (
                        _format_instant(v["revoked_at"]) if v["revoked_at"] is not None else None
                    ),
                }
                for v in self._consents[consent_id]
            ]
            consents.append({"consent_id": consent_id, "versions": versions})
        payload = {"format": SNAPSHOT_FORMAT, "version": SNAPSHOT_VERSION, "consents": consents}
        return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))

    def import_snapshot(self, data: Any) -> None:
        """从快照整体恢复;任何非法都抛出 InvalidConsentSnapshotError 且不留部分数据。"""
        self._consents = _parse_snapshot(data)

    @classmethod
    def from_snapshot(cls, data: Any) -> "ConsentRegistry":
        """从快照构造一个新注册表。"""
        registry = cls()
        registry.import_snapshot(data)
        return registry

    # ------------------------------------------------------------------
    # 内部
    # ------------------------------------------------------------------

    def _versions(self, consent_id: str) -> list[dict]:
        if not isinstance(consent_id, str) or not consent_id:
            raise InvalidConsentError("consent_id must be a non-empty string")
        versions = self._consents.get(consent_id)
        if versions is None:
            raise ConsentNotFoundError(f"unknown consent_id: {consent_id}")
        return versions

    @staticmethod
    def _build_record(fields: dict) -> dict:
        consent_id = _parse_identifier(fields.get("consent_id"), "consent_id", InvalidConsentError)
        subject_id = _parse_identifier(fields.get("subject_id"), "subject_id", InvalidConsentError)
        purposes = _parse_string_set(
            _require(fields, "purposes", InvalidConsentError), "purposes", InvalidConsentError
        )
        data_categories = _parse_string_set(
            _require(fields, "data_categories", InvalidConsentError),
            "data_categories",
            InvalidConsentError,
        )
        valid_from = _parse_instant(
            _require(fields, "valid_from", InvalidConsentError), "valid_from", InvalidConsentError
        )
        valid_until_value = fields.get("valid_until")
        valid_until = (
            None
            if valid_until_value is None
            else _parse_instant(valid_until_value, "valid_until", InvalidConsentError)
        )
        if valid_until is not None and valid_until <= valid_from:
            raise InvalidConsentError("valid_until must be later than valid_from")
        return {
            "consent_id": consent_id,
            "subject_id": subject_id,
            "purposes": purposes,
            "data_categories": data_categories,
            "valid_from": valid_from,
            "valid_until": valid_until,
            "status": ACTIVE,
            "revoked_at": None,
        }

    def _commit(self, record: dict, must_exist: bool) -> dict:
        consent_id = record["consent_id"]
        versions = self._consents.get(consent_id)
        if versions is None:
            if must_exist:
                raise ConsentNotFoundError(f"unknown consent_id: {consent_id}")
            record["version"] = 1
            self._consents[consent_id] = [record]
            return _public_record(record)
        latest = versions[-1]
        if latest["status"] == ACTIVE and _same_content(latest, record):
            return _public_record(latest)
        record["version"] = latest["version"] + 1
        versions.append(record)
        return _public_record(record)


def _same_content(current: dict, candidate: dict) -> bool:
    return (
        current["subject_id"] == candidate["subject_id"]
        and current["purposes"] == candidate["purposes"]
        and current["data_categories"] == candidate["data_categories"]
        and current["valid_from"] == candidate["valid_from"]
        and current["valid_until"] == candidate["valid_until"]
    )


def _active_at(record: dict, moment: datetime) -> bool:
    """撤销从 revoked_at 起生效,之前仍视为有效。"""
    return record["status"] == ACTIVE or record["revoked_at"] > moment


def _expired_at(record: dict, moment: datetime) -> bool:
    """等于失效时间即视为已失效。"""
    return record["valid_until"] is not None and moment >= record["valid_until"]


def _public_record(record: dict) -> dict:
    """返回与内部状态隔离的记录视图;frozenset 与 datetime 本身不可变。"""
    return {
        "consent_id": record["consent_id"],
        "subject_id": record["subject_id"],
        "purposes": frozenset(record["purposes"]),
        "data_categories": frozenset(record["data_categories"]),
        "valid_from": record["valid_from"],
        "valid_until": record["valid_until"],
        "status": record["status"],
        "version": record["version"],
        "revoked_at": record["revoked_at"],
    }


def _deny(reason: str) -> dict:
    return {"decision": DENY, "reason": reason, "consent_id": None, "version": None}


def _parse_snapshot(data: Any) -> dict[str, list[dict]]:
    """完整解析并校验快照;任何非法都抛出 InvalidConsentSnapshotError。"""
    if isinstance(data, (bytes, bytearray)):
        try:
            data = bytes(data).decode("utf-8")
        except UnicodeDecodeError:
            raise InvalidConsentSnapshotError("snapshot is not valid UTF-8") from None
    if isinstance(data, str):
        try:
            payload = json.loads(data)
        except json.JSONDecodeError:
            raise InvalidConsentSnapshotError("snapshot is not valid JSON") from None
    else:
        payload = data
    if not isinstance(payload, dict):
        raise InvalidConsentSnapshotError("snapshot must be a JSON object")
    if payload.get("format") != SNAPSHOT_FORMAT:
        raise InvalidConsentSnapshotError("snapshot format is not recognized")
    version = payload.get("version")
    if isinstance(version, bool) or version != SNAPSHOT_VERSION:
        raise InvalidConsentSnapshotError("snapshot version is not supported")
    raw_consents = payload.get("consents")
    if not isinstance(raw_consents, list):
        raise InvalidConsentSnapshotError("snapshot consents must be an array")

    state: dict[str, list[dict]] = {}
    for raw_consent in raw_consents:
        if not isinstance(raw_consent, dict):
            raise InvalidConsentSnapshotError("each snapshot consent must be an object")
        consent_id = _parse_identifier(
            raw_consent.get("consent_id"), "consent_id", InvalidConsentSnapshotError
        )
        if consent_id in state:
            raise InvalidConsentSnapshotError("consent_id must be unique within the snapshot")
        raw_versions = raw_consent.get("versions")
        if not isinstance(raw_versions, list) or not raw_versions:
            raise InvalidConsentSnapshotError("each snapshot consent must carry versions")
        versions = [
            _parse_snapshot_version(raw, expected, consent_id)
            for expected, raw in enumerate(raw_versions, start=1)
        ]
        state[consent_id] = versions
    return state


def _parse_snapshot_version(raw: Any, expected_version: int, consent_id: str) -> dict:
    if not isinstance(raw, dict):
        raise InvalidConsentSnapshotError("each snapshot version must be an object")
    version = raw.get("version")
    if isinstance(version, bool) or not isinstance(version, int) or version != expected_version:
        raise InvalidConsentSnapshotError("versions must increase consecutively from 1")
    subject_id = _parse_identifier(raw.get("subject_id"), "subject_id", InvalidConsentSnapshotError)
    purposes = _parse_snapshot_string_set(raw.get("purposes"), "purposes")
    data_categories = _parse_snapshot_string_set(raw.get("data_categories"), "data_categories")
    valid_from = _parse_instant(raw.get("valid_from"), "valid_from", InvalidConsentSnapshotError)
    valid_until_raw = raw.get("valid_until")
    valid_until = (
        None
        if valid_until_raw is None
        else _parse_instant(valid_until_raw, "valid_until", InvalidConsentSnapshotError)
    )
    if valid_until is not None and valid_until <= valid_from:
        raise InvalidConsentSnapshotError("valid_until must be later than valid_from")
    status = raw.get("status")
    if status not in (ACTIVE, REVOKED):
        raise InvalidConsentSnapshotError("status must be 'active' or 'revoked'")
    revoked_at_raw = raw.get("revoked_at")
    if status == REVOKED:
        revoked_at = _parse_instant(revoked_at_raw, "revoked_at", InvalidConsentSnapshotError)
        if revoked_at < valid_from:
            raise InvalidConsentSnapshotError("revoked_at must not be earlier than valid_from")
    else:
        if revoked_at_raw is not None:
            raise InvalidConsentSnapshotError("active versions must not carry revoked_at")
        revoked_at = None
    return {
        "consent_id": consent_id,
        "subject_id": subject_id,
        "purposes": purposes,
        "data_categories": data_categories,
        "valid_from": valid_from,
        "valid_until": valid_until,
        "status": status,
        "version": version,
        "revoked_at": revoked_at,
    }


def _parse_snapshot_string_set(value: Any, field: str) -> frozenset[str]:
    if not isinstance(value, list) or not value:
        raise InvalidConsentSnapshotError(f"{field} must be a non-empty array")
    items: set[str] = set()
    for item in value:
        if not isinstance(item, str) or not item:
            raise InvalidConsentSnapshotError(f"{field} must contain only non-empty strings")
        if item in items:
            raise InvalidConsentSnapshotError(f"{field} must not contain duplicates")
        items.add(item)
    return frozenset(items)
