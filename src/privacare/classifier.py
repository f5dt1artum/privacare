"""Sensitive-field classification for medical records.

All logic here is pure and request-scoped: rules and results are derived
solely from the current request payload, so nothing leaks across requests.
"""

from __future__ import annotations

import re
from typing import Any, Iterator

CATEGORIES: tuple[str, ...] = (
    "direct_identifier",
    "contact",
    "clinical",
    "financial",
    "quasi_identifier",
)

SOURCES: tuple[str, ...] = ("schema", "field_name", "value")

_CATEGORY_SET = frozenset(CATEGORIES)

_DIRECT = "direct_identifier"
_CONTACT = "contact"
_CLINICAL = "clinical"
_FINANCIAL = "financial"
_QUASI = "quasi_identifier"


class InvalidRequest(ValueError):
    """The request payload failed structural validation."""


class InvalidSchema(ValueError):
    """The caller-supplied schema is malformed."""


# Field-name keyword rules. ASCII keywords are matched against tokenized
# field names (camelCase and separators split); keywords shorter than 4
# chars — plus a few listed in _EXACT_ASCII — require an exact token match
# so that e.g. "age" does not fire on "dosage". Non-ASCII (Chinese)
# keywords match as plain substrings of the raw field name.
_KEYWORD_RULES: tuple[tuple[str, tuple[str, ...]], ...] = (
    # direct_identifier
    ("id", (_DIRECT,)),
    ("name", (_DIRECT,)),
    ("姓名", (_DIRECT,)),
    ("id_card", (_DIRECT,)),
    ("idcard", (_DIRECT,)),
    ("identity", (_DIRECT,)),
    ("身份证", (_DIRECT,)),
    ("证件", (_DIRECT,)),
    ("passport", (_DIRECT,)),
    ("护照", (_DIRECT,)),
    ("ssn", (_DIRECT,)),
    ("social_security", (_DIRECT,)),
    ("license", (_DIRECT,)),
    ("licence", (_DIRECT,)),
    ("驾驶证", (_DIRECT,)),
    ("驾照", (_DIRECT,)),
    ("medical_record", (_DIRECT,)),
    ("mrn", (_DIRECT,)),
    ("病历号", (_DIRECT,)),
    ("病案号", (_DIRECT,)),
    ("patient_id", (_DIRECT,)),
    ("patient_no", (_DIRECT,)),
    ("患者编号", (_DIRECT,)),
    ("住院号", (_DIRECT,)),
    ("门诊号", (_DIRECT,)),
    ("就诊卡", (_DIRECT,)),
    # contact
    ("email", (_CONTACT,)),
    ("e_mail", (_CONTACT,)),
    ("邮箱", (_CONTACT,)),
    ("电子邮件", (_CONTACT,)),
    ("phone", (_CONTACT,)),
    ("mobile", (_CONTACT,)),
    ("telephone", (_CONTACT,)),
    ("tel", (_CONTACT,)),
    ("手机", (_CONTACT,)),
    ("电话", (_CONTACT,)),
    ("联系方式", (_CONTACT,)),
    ("contact", (_CONTACT,)),
    ("address", (_CONTACT,)),
    ("addr", (_CONTACT,)),
    ("地址", (_CONTACT,)),
    ("住址", (_CONTACT,)),
    ("wechat", (_CONTACT,)),
    ("微信", (_CONTACT,)),
    ("qq", (_CONTACT,)),
    ("fax", (_CONTACT,)),
    ("传真", (_CONTACT,)),
    # clinical
    ("diagnosis", (_CLINICAL,)),
    ("diagnose", (_CLINICAL,)),
    ("诊断", (_CLINICAL,)),
    ("symptom", (_CLINICAL,)),
    ("症状", (_CLINICAL,)),
    ("medical_history", (_CLINICAL,)),
    ("history", (_CLINICAL,)),
    ("病史", (_CLINICAL,)),
    ("chief_complaint", (_CLINICAL,)),
    ("主诉", (_CLINICAL,)),
    ("medication", (_CLINICAL,)),
    ("drug", (_CLINICAL,)),
    ("用药", (_CLINICAL,)),
    ("药品", (_CLINICAL,)),
    ("药物", (_CLINICAL,)),
    ("prescription", (_CLINICAL,)),
    ("处方", (_CLINICAL,)),
    ("lab", (_CLINICAL,)),
    ("test_result", (_CLINICAL,)),
    ("检验", (_CLINICAL,)),
    ("化验", (_CLINICAL,)),
    ("exam", (_CLINICAL,)),
    ("examination", (_CLINICAL,)),
    ("检查", (_CLINICAL,)),
    ("disease", (_CLINICAL,)),
    ("疾病", (_CLINICAL,)),
    ("allergy", (_CLINICAL,)),
    ("allergies", (_CLINICAL,)),
    ("过敏", (_CLINICAL,)),
    ("treatment", (_CLINICAL,)),
    ("治疗", (_CLINICAL,)),
    ("surgery", (_CLINICAL,)),
    ("operation", (_CLINICAL,)),
    ("手术", (_CLINICAL,)),
    ("clinical", (_CLINICAL,)),
    ("临床", (_CLINICAL,)),
    ("icd", (_CLINICAL,)),
    ("pathology", (_CLINICAL,)),
    ("病理", (_CLINICAL,)),
    ("vital", (_CLINICAL,)),
    ("体征", (_CLINICAL,)),
    ("temperature", (_CLINICAL,)),
    ("体温", (_CLINICAL,)),
    ("blood_pressure", (_CLINICAL,)),
    ("血压", (_CLINICAL,)),
    ("heart_rate", (_CLINICAL,)),
    ("心率", (_CLINICAL,)),
    ("height", (_CLINICAL,)),
    ("weight", (_CLINICAL,)),
    ("身高", (_CLINICAL,)),
    ("体重", (_CLINICAL,)),
    ("bmi", (_CLINICAL,)),
    ("condition", (_CLINICAL,)),
    ("病情", (_CLINICAL,)),
    ("doctor", (_CLINICAL,)),
    ("physician", (_CLINICAL,)),
    ("医生", (_CLINICAL,)),
    # financial
    ("bank", (_FINANCIAL,)),
    ("银行", (_FINANCIAL,)),
    ("bank_card", (_FINANCIAL,)),
    ("bankcard", (_FINANCIAL,)),
    ("card_no", (_FINANCIAL,)),
    ("card_number", (_FINANCIAL,)),
    ("卡号", (_FINANCIAL,)),
    ("account", (_FINANCIAL,)),
    ("账号", (_FINANCIAL,)),
    ("账户", (_FINANCIAL,)),
    ("amount", (_FINANCIAL,)),
    ("金额", (_FINANCIAL,)),
    ("fee", (_FINANCIAL,)),
    ("费用", (_FINANCIAL,)),
    ("cost", (_FINANCIAL,)),
    ("收费", (_FINANCIAL,)),
    ("price", (_FINANCIAL,)),
    ("价格", (_FINANCIAL,)),
    ("invoice", (_FINANCIAL,)),
    ("发票", (_FINANCIAL,)),
    ("insurance", (_FINANCIAL,)),
    ("保险", (_FINANCIAL,)),
    ("医保", (_FINANCIAL,)),
    ("payment", (_FINANCIAL,)),
    ("支付", (_FINANCIAL,)),
    ("balance", (_FINANCIAL,)),
    ("余额", (_FINANCIAL,)),
    ("income", (_FINANCIAL,)),
    ("收入", (_FINANCIAL,)),
    ("salary", (_FINANCIAL,)),
    ("工资", (_FINANCIAL,)),
    ("deposit", (_FINANCIAL,)),
    ("押金", (_FINANCIAL,)),
    ("billing", (_FINANCIAL,)),
    ("账单", (_FINANCIAL,)),
    # quasi_identifier
    ("age", (_QUASI,)),
    ("年龄", (_QUASI,)),
    ("gender", (_QUASI,)),
    ("sex", (_QUASI,)),
    ("性别", (_QUASI,)),
    ("birth", (_QUASI,)),
    ("birthday", (_QUASI,)),
    ("dob", (_QUASI,)),
    ("出生", (_QUASI,)),
    ("生日", (_QUASI,)),
    ("occupation", (_QUASI,)),
    ("profession", (_QUASI,)),
    ("job", (_QUASI,)),
    ("职业", (_QUASI,)),
    ("marital", (_QUASI,)),
    ("婚姻", (_QUASI,)),
    ("ethnicity", (_QUASI,)),
    ("ethnic", (_QUASI,)),
    ("nationality", (_QUASI,)),
    ("民族", (_QUASI,)),
    ("race", (_QUASI,)),
    ("city", (_QUASI,)),
    ("城市", (_QUASI,)),
    ("region", (_QUASI,)),
    ("地区", (_QUASI,)),
    ("province", (_QUASI,)),
    ("county", (_QUASI,)),
    ("县", (_QUASI,)),
    ("zip", (_QUASI,)),
    ("postal", (_QUASI,)),
    ("邮编", (_QUASI,)),
    ("education", (_QUASI,)),
    ("学历", (_QUASI,)),
    ("教育", (_QUASI,)),
    ("company", (_QUASI,)),
    ("公司", (_QUASI,)),
    ("employer", (_QUASI,)),
    ("work_unit", (_QUASI,)),
    ("单位", (_QUASI,)),
    ("department", (_QUASI,)),
    ("科室", (_QUASI,)),
    ("hospital", (_QUASI,)),
    ("医院", (_QUASI,)),
)

# ASCII keywords that must match a whole token (plus simple plural) instead
# of any token substring, to avoid false positives like "dosage" -> "age"
# or "example" -> "exam".
_EXACT_ASCII = frozenset(
    keyword
    for keyword, _ in _KEYWORD_RULES
    if keyword.isascii() and len(keyword) < 4
) | {"exam", "race"}

_CAMEL_BOUNDARY = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")
_NON_ALNUM = re.compile(r"[^0-9A-Za-z]+")


def _name_categories(key: str) -> set[str]:
    """Categories implied by a field name, via Chinese/English keywords."""
    if not key:
        return set()
    spaced = _CAMEL_BOUNDARY.sub(" ", key)
    tokens = _NON_ALNUM.sub(" ", spaced).lower().split()
    joined = "_".join(tokens)
    cats: set[str] = set()
    for keyword, keyword_cats in _KEYWORD_RULES:
        if keyword.isascii():
            if keyword in _EXACT_ASCII:
                matched = any(t == keyword or t == keyword + "s" for t in tokens)
            elif "_" in keyword:
                matched = keyword in joined
            else:
                matched = any(keyword in t for t in tokens)
        else:
            matched = keyword in key
        if matched:
            cats.update(keyword_cats)
    return cats


_EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}$")
_MOBILE_RE = re.compile(r"^1[3-9]\d{9}$")
_LANDLINE_RE = re.compile(r"^0\d{9,11}$")
_INTL_PHONE_RE = re.compile(r"^\+\d{7,15}$")
_ID_18_RE = re.compile(r"^\d{17}[0-9Xx]$")
_ID_15_RE = re.compile(r"^\d{15}$")
_BANK_CARD_RE = re.compile(r"^\d{13,19}$")
_PHONE_STRIP_RE = re.compile(r"[\s\-().]+")

_ID_WEIGHTS = (7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2)
_ID_CHECK_CODES = "10X98765432"
_DAYS_IN_MONTH = (31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31)


def _valid_date(month: int, day: int) -> bool:
    return 1 <= month <= 12 and 1 <= day <= _DAYS_IN_MONTH[month - 1]


def _is_cn_id(text: str) -> bool:
    """Mainland China resident ID: 18 digits with checksum, or legacy 15."""
    if _ID_18_RE.fullmatch(text):
        year = int(text[6:10])
        if not 1900 <= year <= 2100:
            return False
        if not _valid_date(int(text[10:12]), int(text[12:14])):
            return False
        total = sum(int(text[i]) * _ID_WEIGHTS[i] for i in range(17))
        return _ID_CHECK_CODES[total % 11] == text[17].upper()
    if _ID_15_RE.fullmatch(text):
        return _valid_date(int(text[8:10]), int(text[10:12]))
    return False


def _luhn_ok(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        n = ord(ch) - 48
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def _is_phone(text: str) -> bool:
    normalized = _PHONE_STRIP_RE.sub("", text)
    if _MOBILE_RE.fullmatch(normalized):
        return True
    if _LANDLINE_RE.fullmatch(normalized):
        return True
    return bool(_INTL_PHONE_RE.fullmatch(normalized))


def _value_categories(value: str) -> set[str]:
    """Categories implied by a string value's format.

    Only well-formed values hit: strings that fail format validation
    (bad ID checksum, non-Luhn card number, ...) yield nothing.
    """
    text = value.strip()
    if len(text) < 5:
        return set()
    cats: set[str] = set()
    if _EMAIL_RE.fullmatch(text):
        cats.add(_CONTACT)
    if _is_phone(text):
        cats.add(_CONTACT)
    if _is_cn_id(text):
        cats.add(_DIRECT)
    if _BANK_CARD_RE.fullmatch(text) and _luhn_ok(text):
        cats.add(_FINANCIAL)
    return cats


def _escape_segment(segment: str) -> str:
    return segment.replace("~", "~0").replace("/", "~1")


def _pointer(segments: tuple[str, ...]) -> str:
    return "".join("/" + _escape_segment(s) for s in segments)


def _iter_leaves(node: Any, segments: tuple[str, ...], key: str) -> Iterator[tuple[tuple[str, ...], str, Any]]:
    """Yield (path segments, nearest field key, value) for every leaf."""
    if isinstance(node, dict):
        for child_key, child in node.items():
            yield from _iter_leaves(child, segments + (child_key,), child_key)
    elif isinstance(node, list):
        for index, child in enumerate(node):
            yield from _iter_leaves(child, segments + (str(index),), key)
    else:
        yield segments, key, node


_MISSING = object()


def _resolve(record: dict, segments: tuple[str, ...]) -> Any:
    node: Any = record
    for segment in segments:
        if isinstance(node, dict):
            if segment not in node:
                return _MISSING
            node = node[segment]
        elif isinstance(node, list):
            if not segment.isdigit():
                return _MISSING
            index = int(segment)
            if index >= len(node):
                return _MISSING
            node = node[index]
        else:
            return _MISSING
    return node


def _parse_pointer(raw: Any) -> tuple[str, ...]:
    if not isinstance(raw, str):
        raise InvalidSchema("schema keys must be JSON pointer strings")
    if raw == "":
        return ()
    if not raw.startswith("/"):
        raise InvalidSchema("schema keys must be JSON pointers starting with '/'")
    segments = []
    for part in raw.split("/")[1:]:
        out = []
        i = 0
        while i < len(part):
            ch = part[i]
            if ch == "~":
                nxt = part[i + 1] if i + 1 < len(part) else ""
                if nxt == "0":
                    out.append("~")
                elif nxt == "1":
                    out.append("/")
                else:
                    raise InvalidSchema("invalid '~' escape in JSON pointer")
                i += 2
            else:
                out.append(ch)
                i += 1
        segments.append("".join(out))
    return tuple(segments)


def _parse_schema_categories(raw: Any) -> tuple[str, ...]:
    if isinstance(raw, str):
        raw = [raw]
    if not isinstance(raw, list) or not raw:
        raise InvalidSchema("schema values must be a category or a non-empty list of categories")
    cats: list[str] = []
    for item in raw:
        if not isinstance(item, str) or item not in _CATEGORY_SET:
            raise InvalidSchema("unsupported category in schema")
        if item not in cats:
            cats.append(item)
    return tuple(cats)


def _record_hits(
    record: dict, rules: list[tuple[tuple[str, ...], tuple[str, ...]]]
) -> dict[tuple[str, ...], tuple[set[str], set[str]]]:
    """Merge schema/field-name/value hits for one record.

    Returns a mapping of leaf path segments to (categories, sources).
    """
    hits: dict[tuple[str, ...], tuple[set[str], set[str]]] = {}

    def hit(segments: tuple[str, ...], cats: set[str] | tuple[str, ...], source: str) -> None:
        entry = hits.get(segments)
        if entry is None:
            entry = hits[segments] = (set(), set())
        entry[0].update(cats)
        entry[1].add(source)

    for segments, cats in rules:
        node = _resolve(record, segments)
        if node is _MISSING:
            continue
        for leaf_segments, _key, _value in _iter_leaves(node, segments, ""):
            hit(leaf_segments, cats, "schema")

    for leaf_segments, key, value in _iter_leaves(record, (), ""):
        name_cats = _name_categories(key)
        if name_cats:
            hit(leaf_segments, name_cats, "field_name")
        if isinstance(value, str):
            value_cats = _value_categories(value)
            if value_cats:
                hit(leaf_segments, value_cats, "value")
    return hits


def _classify_records(records: list[dict], rules: list[tuple[tuple[str, ...], tuple[str, ...]]]) -> list[dict]:
    results = []
    for index, record in enumerate(records):
        hits = _record_hits(record, rules)
        fields = [
            {
                "path": _pointer(segments),
                "categories": [c for c in CATEGORIES if c in cats],
                "sources": [s for s in SOURCES if s in sources],
            }
            for segments, (cats, sources) in sorted(hits.items(), key=lambda item: _pointer(item[0]))
        ]
        results.append({"index": index, "fields": fields})
    return results


def _validate_records(payload: Any) -> list[dict]:
    """Shared structural validation for record-batch request payloads."""
    if not isinstance(payload, dict):
        raise InvalidRequest("request body must be a JSON object")
    records = payload.get("records")
    if not isinstance(records, list) or not records:
        raise InvalidRequest("records must be a non-empty array")
    for record in records:
        if not isinstance(record, dict):
            raise InvalidRequest("each record must be an object")
    return records


def _parse_rules(schema: Any) -> list[tuple[tuple[str, ...], tuple[str, ...]]]:
    """Validate an optional request schema into (segments, categories) rules."""
    if schema is None:
        return []
    if not isinstance(schema, dict):
        raise InvalidSchema("schema must be an object")
    return [
        (_parse_pointer(pointer), _parse_schema_categories(cats))
        for pointer, cats in schema.items()
    ]


def classify_request(payload: Any) -> list[dict]:
    """Validate a /v1/classify payload and classify every record."""
    records = _validate_records(payload)
    rules = _parse_rules(payload.get("schema"))
    return _classify_records(records, rules)
