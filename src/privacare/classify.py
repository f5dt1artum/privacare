"""医疗记录敏感字段识别.

结合字段名语义(中英文)与值格式校验, 输出字段级敏感类别。
类别固定为: direct_identifier / contact / clinical / financial / quasi_identifier,
来源固定为: schema / field_name / value。
"""

from __future__ import annotations

import re
from typing import Any, Iterable

CATEGORY_ORDER = [
    "direct_identifier",
    "contact",
    "clinical",
    "financial",
    "quasi_identifier",
]
SOURCE_ORDER = ["schema", "field_name", "value"]
CATEGORIES = frozenset(CATEGORY_ORDER)


class SchemaError(ValueError):
    """Raised when the per-request schema is malformed."""


# ---------------------------------------------------------------------------
# 字段名语义识别

_EN_TOKEN = {
    "direct_identifier": {
        "name", "idcard", "ssn", "passport", "identity",
    },
    "contact": {
        "email", "mail", "phone", "mobile", "telephone", "tel",
        "address", "addr", "wechat",
    },
    "clinical": {
        "diagnosis", "diagnose", "disease", "symptom", "medication",
        "allergy", "treatment", "prescription", "surgery", "operation",
        "icd", "icd10", "lab", "pathology", "complaint", "vital",
        "temperature", "pulse",
    },
    "financial": {
        "account", "insurance", "amount", "price", "cost", "fee",
        "payment", "salary", "income", "balance", "bankcard",
    },
    "quasi_identifier": {
        "age", "gender", "sex", "dob", "birthday", "birthdate",
        "zip", "zipcode", "postcode", "occupation", "job", "city",
        "region", "province", "marital", "ethnicity", "nation",
    },
}

# 去掉分隔符后的完整字段名(处理 id_card / bankCard 这类复合写法)
_EN_JOINED = {
    "direct_identifier": {
        "idcard", "patientname", "fullname", "realname", "idnumber",
        "passportnumber", "socialsecuritynumber",
    },
    "contact": {
        "phonenumber", "mobilenumber", "telephonenumber", "emailaddress",
        "homeaddress", "contactphone", "contactnumber",
    },
    "clinical": {
        "medicalhistory", "chiefcomplaint", "labresult", "testresult",
        "bloodpressure", "heartrate",
    },
    "financial": {
        "bankcard", "cardnumber", "bankaccount", "accountnumber",
        "insurancenumber",
    },
    "quasi_identifier": {
        "birthdate", "dateofbirth", "zipcode", "postalcode",
    },
}

_CN_SUBSTR = {
    "direct_identifier": [
        "姓名", "名字", "身份证", "护照", "社保卡", "驾驶证", "军官证", "通行证",
    ],
    "contact": [
        "邮箱", "电话", "手机", "联系方式", "地址", "住址", "通讯", "微信",
    ],
    "clinical": [
        "诊断", "疾病", "症状", "病史", "用药", "药品", "药物", "过敏",
        "检验", "检查", "化验", "手术", "治疗", "主诉", "处方", "病历",
        "体温", "血压", "心率", "病理", "影像", "体征",
    ],
    "financial": [
        "银行卡", "卡号", "账户", "账号", "医保", "保险",
        "费用", "金额", "价格", "收费", "工资", "收入",
    ],
    "quasi_identifier": [
        "年龄", "性别", "出生", "生日", "邮编", "职业",
        "婚姻", "民族", "籍贯", "城市", "地区", "省份",
    ],
}

_TOKEN_RE = re.compile(
    r"[A-Z]+(?![a-z0-9])|[A-Z][a-z0-9]*|[a-z0-9]+|[一-鿿]+"
)


def _tokens(key: str) -> list[str]:
    return [m.group(0).lower() for m in _TOKEN_RE.finditer(key)]


def name_categories(key: str) -> set[str]:
    """按字段名语义推断类别, 不依赖字段值。"""
    cats: set[str] = set()
    toks = _tokens(key)
    if not toks:
        return cats
    tok_set = set(toks)
    # 兼容常见复数写法: phones -> phone
    tok_set |= {t[:-1] for t in toks if len(t) > 3 and t.endswith("s")}
    joined = "".join(toks)
    for cat in CATEGORY_ORDER:
        if tok_set & _EN_TOKEN[cat] or joined in _EN_JOINED[cat]:
            cats.add(cat)
            continue
        if any(sub in tok for tok in toks for sub in _CN_SUBSTR[cat]):
            cats.add(cat)
    return cats


# ---------------------------------------------------------------------------
# 值格式识别

_EMAIL_RE = re.compile(
    r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}$"
)
_MOBILE_RE = re.compile(r"^(?:\+?86[- ]?)?1[3-9]\d{9}$")
_LANDLINE_RE = re.compile(r"^0\d{2,3}-?\d{7,8}$")
_ID_RE = re.compile(r"^\d{17}[0-9Xx]$")
_BANK_RE = re.compile(r"^\d{13,19}$")

_ID_WEIGHTS = (7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2)
_ID_CHECK = "10X98765432"


def _valid_cn_id(value: str) -> bool:
    if not _ID_RE.match(value):
        return False
    total = sum(int(value[i]) * _ID_WEIGHTS[i] for i in range(17))
    return _ID_CHECK[total % 11] == value[17].upper()


def _luhn_ok(value: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(value)):
        d = ord(ch) - 48
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def value_categories(value: Any) -> set[str]:
    """按值格式推断类别; 仅检查非空字符串, 且必须通过严格格式校验。"""
    if not isinstance(value, str) or not value:
        return set()
    cats: set[str] = set()
    if _EMAIL_RE.match(value):
        cats.add("contact")
    if _MOBILE_RE.match(value) or _LANDLINE_RE.match(value):
        cats.add("contact")
    if _valid_cn_id(value):
        cats.add("direct_identifier")
    if _BANK_RE.match(value) and _luhn_ok(value):
        cats.add("financial")
    return cats


# ---------------------------------------------------------------------------
# JSON Pointer (RFC 6901)

def escape_segment(segment: str) -> str:
    return segment.replace("~", "~0").replace("/", "~1")


def parse_pointer(pointer: Any) -> list[str]:
    if not isinstance(pointer, str):
        raise SchemaError(f"schema pointer must be a string: {pointer!r}")
    if pointer == "":
        return []
    if not pointer.startswith("/"):
        raise SchemaError(f"invalid JSON pointer: {pointer!r}")
    segments: list[str] = []
    for raw in pointer.split("/")[1:]:
        buf: list[str] = []
        i = 0
        while i < len(raw):
            ch = raw[i]
            if ch == "~":
                if i + 1 >= len(raw) or raw[i + 1] not in "01":
                    raise SchemaError(f"invalid JSON pointer escape: {pointer!r}")
                buf.append("~" if raw[i + 1] == "0" else "/")
                i += 2
            else:
                buf.append(ch)
                i += 1
        segments.append("".join(buf))
    return segments


_MISSING = object()


def _resolve(doc: Any, segments: Iterable[str]) -> Any:
    node = doc
    for seg in segments:
        if isinstance(node, dict):
            if seg not in node:
                return _MISSING
            node = node[seg]
        elif isinstance(node, list):
            if not seg.isdigit():
                return _MISSING
            idx = int(seg)
            if idx >= len(node):
                return _MISSING
            node = node[idx]
        else:
            return _MISSING
    return node


# ---------------------------------------------------------------------------
# 记录分类

def _normalize_schema_categories(raw: Any, pointer: str) -> set[str]:
    items = raw if isinstance(raw, list) else [raw]
    if isinstance(raw, list) and not raw:
        raise SchemaError(f"schema category list is empty for {pointer!r}")
    cats: set[str] = set()
    for item in items:
        if not isinstance(item, str) or item not in CATEGORIES:
            raise SchemaError(f"unsupported category for {pointer!r}: {item!r}")
        cats.add(item)
    return cats


def _classify_record(record: dict, schema_hits: list[tuple[list[str], set[str]]]) -> list[dict]:
    hits: dict[str, dict[str, set[str]]] = {}

    def add(path: str, cats: Iterable[str], source: str) -> None:
        entry = hits.setdefault(path, {"categories": set(), "sources": set()})
        entry["categories"].update(cats)
        entry["sources"].add(source)

    def walk(node: Any, path: str, key: str | None) -> None:
        if key is not None:
            cats = name_categories(key)
            if cats:
                add(path, cats, "field_name")
        if isinstance(node, dict):
            for k, v in node.items():
                walk(v, f"{path}/{escape_segment(k)}", k)
        elif isinstance(node, list):
            for i, v in enumerate(node):
                walk(v, f"{path}/{i}", None)
        else:
            cats = value_categories(node)
            if cats:
                add(path, cats, "value")

    walk(record, "", None)

    for segments, cats in schema_hits:
        if _resolve(record, segments) is _MISSING:
            continue
        pointer = "".join(f"/{escape_segment(s)}" for s in segments)
        add(pointer, cats, "schema")

    return [
        {
            "path": path,
            "categories": [c for c in CATEGORY_ORDER if c in entry["categories"]],
            "sources": [s for s in SOURCE_ORDER if s in entry["sources"]],
        }
        for path, entry in sorted(hits.items())
    ]


def classify_records(records: list[dict], schema: dict | None = None) -> list[list[dict]]:
    """对每条记录输出按路径字典序排列的敏感字段列表。

    schema 仅作用于本次调用; 解析失败抛 SchemaError。
    """
    schema_hits: list[tuple[list[str], set[str]]] = []
    for pointer, raw in (schema or {}).items():
        segments = parse_pointer(pointer)
        cats = _normalize_schema_categories(raw, pointer)
        schema_hits.append((segments, cats))
    return [_classify_record(record, schema_hits) for record in records]
