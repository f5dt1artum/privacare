"""进程内同意登记与用途约束评估。

``ConsentRegistry`` 在调用方进程内维护同意记录：登记、更新、撤销、查询、
评估与确定性快照。每条同意保留完整版本历史，历史不可改写；撤销与内容
变化都产生递增的新版本。时间一律按带时区的 ISO 8601 语义比较，数据类别
与用途集合采用精确字符串匹配。

本模块与请求级的 ``privacare.consent`` 相互独立：只有显式使用
``ConsentRegistry`` 的流程受这些规则约束，既有公开入口与函数语义不变。
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Iterable

__all__ = [
    "ALLOW",
    "DENY",
    "REASON_ALLOWED",
    "REASON_NO_CONSENT",
    "REASON_NOT_YET_EFFECTIVE",
    "REASON_REVOKED",
    "REASON_EXPIRED",
    "REASON_PURPOSE_NOT_ALLOWED",
    "REASON_DATA_CATEGORY_NOT_ALLOWED",
    "STATUS_ACTIVE",
    "STATUS_REVOKED",
    "ConsentRecord",
    "ConsentDecision",
    "ConsentRegistry",
    "InvalidConsentError",
    "ConsentNotFoundError",
    "InvalidConsentSnapshotError",
]

ALLOW = "ALLOW"
DENY = "DENY"

REASON_ALLOWED = "ALLOWED"
REASON_NO_CONSENT = "NO_CONSENT"
REASON_NOT_YET_EFFECTIVE = "NOT_YET_EFFECTIVE"
REASON_REVOKED = "REVOKED"
REASON_EXPIRED = "EXPIRED"
REASON_PURPOSE_NOT_ALLOWED = "PURPOSE_NOT_ALLOWED"
REASON_DATA_CATEGORY_NOT_ALLOWED = "DATA_CATEGORY_NOT_ALLOWED"

STATUS_ACTIVE = "active"
STATUS_REVOKED = "revoked"

# 拒绝原因的唯一化优先级（越靠前优先级越高）。
_DENY_PRIORITY = (
    REASON_REVOKED,
    REASON_EXPIRED,
    REASON_PURPOSE_NOT_ALLOWED,
    REASON_DATA_CATEGORY_NOT_ALLOWED,
)

# ISO 8601 日期时间，必须携带数值时区偏移或 "Z"。
_ISO8601_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$"
)

_SNAPSHOT_FORMAT = "privacare.consent_registry.snapshot"
_SNAPSHOT_VERSION = 1

_VERSION_FIELDS = (
    "version",
    "subject_id",
    "purposes",
    "data_categories",
    "effective_from",
    "expires_at",
    "status",
    "revoked_at",
)


class InvalidConsentError(ValueError):
    """同意记录、撤销或评估请求的字段非法。"""


class ConsentNotFoundError(LookupError):
    """查询、更新或撤销了不存在的 consent_id。"""


class InvalidConsentSnapshotError(ValueError):
    """快照的格式、版本或记录关系非法。"""


def _parse_time(value: Any, field: str, error: type[ValueError]) -> datetime:
    """解析带时区的 ISO 8601 时间；接受字符串或感知时区的 datetime。"""
    if isinstance(value, datetime):
        if value.tzinfo is None or value.tzinfo.utcoffset(value) is None:
            raise error(f"{field} must carry a timezone")
        return value
    if isinstance(value, str) and _ISO8601_RE.match(value):
        try:
            return datetime.fromisoformat(value)
        except ValueError:
            raise error(f"{field} must be a valid ISO 8601 date-time") from None
    raise error(f"{field} must be an ISO 8601 date-time with a timezone offset")


def _format_time(value: datetime) -> str:
    """以规范 UTC 形式序列化时间，保证相同状态的快照字节一致。"""
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _require_text(value: Any, field: str, error: type[ValueError]) -> str:
    if not isinstance(value, str) or not value:
        raise error(f"{field} must be a non-empty string")
    return value


def _require_string_set(
    value: Any, field: str, error: type[ValueError]
) -> frozenset[str]:
    if isinstance(value, (str, bytes)) or not isinstance(
        value, (list, tuple, set, frozenset)
    ):
        raise error(f"{field} must be a non-empty collection of strings")
    if not value:
        raise error(f"{field} must not be empty")
    seen: set[str] = set()
    for item in value:
        if not isinstance(item, str) or not item:
            raise error(f"{field} must contain only non-empty strings")
        if item in seen:
            raise error(f"{field} must not contain duplicates")
        seen.add(item)
    return frozenset(value)


@dataclass(frozen=True)
class ConsentRecord:
    """一条同意的单个版本；不可变，集合为 frozenset。"""

    consent_id: str
    subject_id: str
    data_categories: frozenset[str]
    purposes: frozenset[str]
    effective_from: datetime
    expires_at: datetime | None
    status: str
    version: int
    revoked_at: datetime | None

    def is_effective_at(self, moment: datetime) -> bool:
        """等于生效时间即视为已生效。"""
        return self.effective_from <= moment

    def is_expired_at(self, moment: datetime) -> bool:
        """等于失效时间即视为已失效；无失效时间永不失效。"""
        return self.expires_at is not None and self.expires_at <= moment

    def is_revoked_at(self, moment: datetime) -> bool:
        """撤销自撤销时间起生效。"""
        return self.status == STATUS_REVOKED and self.revoked_at <= moment

    def covers(self, purpose: str, data_categories: frozenset[str]) -> bool:
        """同一记录同时覆盖指定用途与全部所需类别。"""
        return purpose in self.purposes and data_categories <= self.data_categories


@dataclass(frozen=True)
class ConsentDecision:
    """评估结果；未允许时 consent_id 与 version 为 None。"""

    decision: str
    reason: str
    consent_id: str | None
    version: int | None

    @property
    def allowed(self) -> bool:
        return self.decision == ALLOW


class ConsentRegistry:
    """同意登记处：登记、更新、撤销、查询、评估与快照。"""

    def __init__(self) -> None:
        # consent_id -> 按版本升序的 ConsentRecord 列表，历史不可改写。
        self._consents: dict[str, list[ConsentRecord]] = {}

    # ------------------------------------------------------------------
    # 登记与生命周期
    # ------------------------------------------------------------------
    def register(
        self,
        consent_id: str,
        subject_id: str,
        data_categories: Iterable[str],
        purposes: Iterable[str],
        effective_from: str | datetime,
        expires_at: str | datetime | None = None,
    ) -> ConsentRecord:
        """登记一条同意；相同 consent_id 与内容的重复登记幂等。

        内容（主体、类别、用途、生效与失效时间）相对最新版本发生变化时
        产生递增的新版本并保留历史；已撤销的同意重新登记会得到新的
        active 版本。
        """
        consent_id = _require_text(consent_id, "consent_id", InvalidConsentError)
        subject_id = _require_text(subject_id, "subject_id", InvalidConsentError)
        categories = _require_string_set(
            data_categories, "data_categories", InvalidConsentError
        )
        purpose_set = _require_string_set(purposes, "purposes", InvalidConsentError)
        start = _parse_time(effective_from, "effective_from", InvalidConsentError)
        end = (
            None
            if expires_at is None
            else _parse_time(expires_at, "expires_at", InvalidConsentError)
        )
        if end is not None and end <= start:
            raise InvalidConsentError("expires_at must be later than effective_from")

        versions = self._consents.get(consent_id)
        if versions:
            latest = versions[-1]
            if (
                latest.status == STATUS_ACTIVE
                and latest.subject_id == subject_id
                and latest.data_categories == categories
                and latest.purposes == purpose_set
                and latest.effective_from == start
                and latest.expires_at == end
            ):
                return latest
            version = latest.version + 1
        else:
            versions = self._consents[consent_id] = []
            version = 1

        record = ConsentRecord(
            consent_id=consent_id,
            subject_id=subject_id,
            data_categories=categories,
            purposes=purpose_set,
            effective_from=start,
            expires_at=end,
            status=STATUS_ACTIVE,
            version=version,
            revoked_at=None,
        )
        versions.append(record)
        return record

    def update(
        self,
        consent_id: str,
        subject_id: str,
        data_categories: Iterable[str],
        purposes: Iterable[str],
        effective_from: str | datetime,
        expires_at: str | datetime | None = None,
    ) -> ConsentRecord:
        """更新已存在的同意；语义与登记一致，但目标必须已存在。"""
        if consent_id not in self._consents:
            raise ConsentNotFoundError(f"unknown consent_id: {consent_id!r}")
        return self.register(
            consent_id,
            subject_id,
            data_categories,
            purposes,
            effective_from,
            expires_at,
        )

    def revoke(self, consent_id: str, revoked_at: str | datetime) -> ConsentRecord:
        """撤销同意：产生一个 status 为 revoked 的新版本，不改写历史。

        以相同撤销时间重复撤销同一同意是幂等的。
        """
        versions = self._consents.get(consent_id)
        if versions is None:
            raise ConsentNotFoundError(f"unknown consent_id: {consent_id!r}")
        moment = _parse_time(revoked_at, "revoked_at", InvalidConsentError)
        latest = versions[-1]
        if latest.status == STATUS_REVOKED:
            if latest.revoked_at == moment:
                return latest
            raise InvalidConsentError("consent is already revoked")
        if moment < latest.effective_from:
            raise InvalidConsentError(
                "revoked_at must not be earlier than effective_from"
            )
        record = ConsentRecord(
            consent_id=latest.consent_id,
            subject_id=latest.subject_id,
            data_categories=latest.data_categories,
            purposes=latest.purposes,
            effective_from=latest.effective_from,
            expires_at=latest.expires_at,
            status=STATUS_REVOKED,
            version=latest.version + 1,
            revoked_at=moment,
        )
        versions.append(record)
        return record

    # ------------------------------------------------------------------
    # 查询
    # ------------------------------------------------------------------
    def get(self, consent_id: str) -> ConsentRecord:
        """返回指定同意的最新版本。"""
        versions = self._consents.get(consent_id)
        if versions is None:
            raise ConsentNotFoundError(f"unknown consent_id: {consent_id!r}")
        return versions[-1]

    def history(self, consent_id: str) -> tuple[ConsentRecord, ...]:
        """按版本升序返回全部历史；返回值为不可变的记录元组。"""
        versions = self._consents.get(consent_id)
        if versions is None:
            raise ConsentNotFoundError(f"unknown consent_id: {consent_id!r}")
        return tuple(versions)

    def __contains__(self, consent_id: str) -> bool:
        return consent_id in self._consents

    def __len__(self) -> int:
        return len(self._consents)

    # ------------------------------------------------------------------
    # 评估
    # ------------------------------------------------------------------
    def evaluate(
        self,
        subject_id: str,
        purpose: str,
        data_categories: Iterable[str],
        evaluated_at: str | datetime,
    ) -> ConsentDecision:
        """判定指定主体在评估时间是否允许以单个用途使用所需类别集合。

        只有该主体某条最新版本记录同时覆盖全部所需类别与指定用途，
        且评估时已经生效、尚未失效且未撤销，结果才是 ALLOW。
        """
        subject_id = _require_text(subject_id, "subject_id", InvalidConsentError)
        purpose = _require_text(purpose, "purpose", InvalidConsentError)
        required = _require_string_set(
            data_categories, "data_categories", InvalidConsentError
        )
        moment = _parse_time(evaluated_at, "evaluated_at", InvalidConsentError)

        records = [
            versions[-1]
            for versions in self._consents.values()
            if versions[-1].subject_id == subject_id
        ]
        if not records:
            return ConsentDecision(DENY, REASON_NO_CONSENT, None, None)

        effective = [r for r in records if r.is_effective_at(moment)]
        if not effective:
            return ConsentDecision(DENY, REASON_NOT_YET_EFFECTIVE, None, None)

        reasons: set[str] = set()
        allowed: list[ConsentRecord] = []
        for record in effective:
            if record.is_revoked_at(moment):
                reasons.add(REASON_REVOKED)
            elif record.is_expired_at(moment):
                reasons.add(REASON_EXPIRED)
            elif purpose not in record.purposes:
                reasons.add(REASON_PURPOSE_NOT_ALLOWED)
            elif not required <= record.data_categories:
                reasons.add(REASON_DATA_CATEGORY_NOT_ALLOWED)
            else:
                allowed.append(record)

        if allowed:
            # 多条覆盖时确定性地选择版本最高、consent_id 字典序最小者。
            best = min(allowed, key=lambda r: (-r.version, r.consent_id))
            return ConsentDecision(ALLOW, REASON_ALLOWED, best.consent_id, best.version)
        for reason in _DENY_PRIORITY:
            if reason in reasons:
                return ConsentDecision(DENY, reason, None, None)
        raise AssertionError("unreachable: effective records always classify")

    # ------------------------------------------------------------------
    # 快照
    # ------------------------------------------------------------------
    def export_snapshot(self) -> str:
        """导出确定性 JSON 快照；相同状态重复导出的字节一致。"""
        consents = []
        for consent_id in sorted(self._consents):
            versions = [
                _version_to_json(record) for record in self._consents[consent_id]
            ]
            consents.append({"consent_id": consent_id, "versions": versions})
        payload = {
            "format": _SNAPSHOT_FORMAT,
            "version": _SNAPSHOT_VERSION,
            "consents": consents,
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":"))

    @classmethod
    def import_snapshot(cls, snapshot: str | bytes) -> "ConsentRegistry":
        """从快照完整恢复记录、版本与撤销时间，返回新的注册表。"""
        registry = cls()
        registry.load_snapshot(snapshot)
        return registry

    def load_snapshot(self, snapshot: str | bytes) -> None:
        """以快照替换当前状态；导入失败时不留下部分数据。"""
        state = _parse_snapshot(snapshot)
        self._consents = state


def _version_to_json(record: ConsentRecord) -> dict:
    return {
        "version": record.version,
        "subject_id": record.subject_id,
        "purposes": sorted(record.purposes),
        "data_categories": sorted(record.data_categories),
        "effective_from": _format_time(record.effective_from),
        "expires_at": (
            None if record.expires_at is None else _format_time(record.expires_at)
        ),
        "status": record.status,
        "revoked_at": (
            None if record.revoked_at is None else _format_time(record.revoked_at)
        ),
    }


def _parse_snapshot(snapshot: str | bytes) -> dict[str, list[ConsentRecord]]:
    """完整校验快照并构建状态；任何非法都抛 InvalidConsentSnapshotError。"""
    error = InvalidConsentSnapshotError
    if isinstance(snapshot, (bytes, bytearray)):
        try:
            snapshot = bytes(snapshot).decode("utf-8")
        except UnicodeDecodeError:
            raise error("snapshot must be valid UTF-8") from None
    if not isinstance(snapshot, str):
        raise error("snapshot must be a JSON string or bytes")
    try:
        payload = json.loads(snapshot)
    except json.JSONDecodeError:
        raise error("snapshot is not valid JSON") from None
    if not isinstance(payload, dict):
        raise error("snapshot must be a JSON object")
    if payload.get("format") != _SNAPSHOT_FORMAT:
        raise error("snapshot format is not recognized")
    version = payload.get("version")
    if isinstance(version, bool) or version != _SNAPSHOT_VERSION:
        raise error("snapshot version is not supported")
    raw_consents = payload.get("consents")
    if not isinstance(raw_consents, list):
        raise error("snapshot consents must be an array")

    state: dict[str, list[ConsentRecord]] = {}
    for entry in raw_consents:
        if not isinstance(entry, dict):
            raise error("each consent entry must be an object")
        consent_id = entry.get("consent_id")
        if not isinstance(consent_id, str) or not consent_id:
            raise error("consent_id must be a non-empty string")
        if consent_id in state:
            raise error(f"duplicate consent_id: {consent_id!r}")
        raw_versions = entry.get("versions")
        if not isinstance(raw_versions, list) or not raw_versions:
            raise error("versions must be a non-empty array")
        records = [_parse_snapshot_version(raw, consent_id) for raw in raw_versions]
        if [r.version for r in records] != list(range(1, len(records) + 1)):
            raise error("versions must increase consecutively from 1 per consent")
        state[consent_id] = records
    return state


def _parse_snapshot_version(raw: Any, consent_id: str) -> ConsentRecord:
    error = InvalidConsentSnapshotError
    if not isinstance(raw, dict) or set(raw) != set(_VERSION_FIELDS):
        raise error("each version must carry exactly the consent fields")
    version = raw["version"]
    if isinstance(version, bool) or not isinstance(version, int) or version < 1:
        raise error("version must be a positive integer")
    subject_id = _require_text(raw["subject_id"], "subject_id", error)
    purposes = _require_string_set(raw["purposes"], "purposes", error)
    categories = _require_string_set(raw["data_categories"], "data_categories", error)
    effective_from = _parse_time(raw["effective_from"], "effective_from", error)
    expires_raw = raw["expires_at"]
    expires_at = (
        None if expires_raw is None else _parse_time(expires_raw, "expires_at", error)
    )
    if expires_at is not None and expires_at <= effective_from:
        raise error("expires_at must be later than effective_from")
    status = raw["status"]
    if status not in (STATUS_ACTIVE, STATUS_REVOKED):
        raise error("status must be 'active' or 'revoked'")
    revoked_raw = raw["revoked_at"]
    if status == STATUS_REVOKED:
        if revoked_raw is None:
            raise error("a revoked version must carry revoked_at")
        revoked_at = _parse_time(revoked_raw, "revoked_at", error)
        if revoked_at < effective_from:
            raise error("revoked_at must not be earlier than effective_from")
    else:
        if revoked_raw is not None:
            raise error("an active version must not carry revoked_at")
        revoked_at = None
    return ConsentRecord(
        consent_id=consent_id,
        subject_id=subject_id,
        data_categories=categories,
        purposes=purposes,
        effective_from=effective_from,
        expires_at=expires_at,
        status=status,
        version=version,
        revoked_at=revoked_at,
    )
