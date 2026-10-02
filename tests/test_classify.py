import unittest

from privacare.classify import (
    SchemaError,
    classify_records,
    name_categories,
    parse_pointer,
    value_categories,
)


def fields_by_path(fields):
    return {f["path"]: f for f in fields}


class NameCategoryTest(unittest.TestCase):
    def test_english_names(self):
        self.assertEqual(name_categories("patient_name"), {"direct_identifier"})
        self.assertEqual(name_categories("email"), {"contact"})
        self.assertEqual(name_categories("phoneNumber"), {"contact"})
        self.assertEqual(name_categories("diagnosis"), {"clinical"})
        self.assertEqual(name_categories("bank_card"), {"financial"})
        self.assertEqual(name_categories("birth_date"), {"quasi_identifier"})
        self.assertEqual(name_categories("gender"), {"quasi_identifier"})

    def test_chinese_names(self):
        self.assertEqual(name_categories("患者姓名"), {"direct_identifier"})
        self.assertEqual(name_categories("联系电话"), {"contact"})
        self.assertEqual(name_categories("入院诊断"), {"clinical"})
        self.assertEqual(name_categories("银行卡号"), {"financial"})
        self.assertEqual(name_categories("年龄"), {"quasi_identifier"})

    def test_unrelated_names(self):
        self.assertEqual(name_categories("message"), set())
        self.assertEqual(name_categories("record_id"), set())
        self.assertEqual(name_categories("created_at"), set())


class ValueCategoryTest(unittest.TestCase):
    def test_formats(self):
        self.assertEqual(value_categories("a.b@example.com"), {"contact"})
        self.assertEqual(value_categories("13800138000"), {"contact"})
        self.assertEqual(value_categories("021-62345678"), {"contact"})
        self.assertEqual(
            value_categories("110101199003078005"), {"direct_identifier"}
        )
        self.assertEqual(value_categories("6222020200112233446"), {"financial"})

    def test_invalid_formats_not_matched(self):
        # 身份证校验位错误
        self.assertEqual(value_categories("110101199003078006"), set())
        # 银行卡 Luhn 校验失败
        self.assertEqual(value_categories("6222020200112233445"), set())
        self.assertEqual(value_categories("not-an-email@"), set())

    def test_non_string_and_trivial_values(self):
        for v in ("", None, True, False, 0, 42, 3.14, "12345"):
            self.assertEqual(value_categories(v), set(), repr(v))


class PointerTest(unittest.TestCase):
    def test_parse_and_escape(self):
        self.assertEqual(parse_pointer(""), [])
        self.assertEqual(parse_pointer("/a~0b/~1"), ["a~b", "/"])
        with self.assertRaises(SchemaError):
            parse_pointer("no-slash")
        with self.assertRaises(SchemaError):
            parse_pointer("/bad~2escape")


class ClassifyRecordsTest(unittest.TestCase):
    def test_nested_and_array_paths(self):
        record = {
            "patient": {"姓名": "张三", "note": "普通备注"},
            "visits": [{"diagnosis": "流感"}, {"diagnosis": "高血压"}],
        }
        (fields,) = classify_records([record])
        by_path = fields_by_path(fields)
        self.assertIn("/patient/姓名", by_path)
        self.assertIn("/visits/0/diagnosis", by_path)
        self.assertIn("/visits/1/diagnosis", by_path)
        self.assertNotIn("/patient/note", by_path)
        self.assertEqual(
            by_path["/patient/姓名"]["categories"], ["direct_identifier"]
        )
        self.assertEqual(by_path["/patient/姓名"]["sources"], ["field_name"])

    def test_pointer_escaping_in_output(self):
        record = {"a/b": {"c~d": {"email": "x@y.com"}}}
        (fields,) = classify_records([record])
        by_path = fields_by_path(fields)
        self.assertIn("/a~1b/c~0d/email", by_path)

    def test_no_echo_of_values(self):
        record = {"email": "secret@example.com"}
        (fields,) = classify_records([record])
        for field in fields:
            self.assertEqual(set(field), {"path", "categories", "sources"})

    def test_schema_merges_and_dedupes(self):
        record = {"custom": {"field": "x"}, "email": "a@b.com"}
        schema = {
            "/custom/field": "clinical",
            "/email": ["contact", "quasi_identifier"],
        }
        (fields,) = classify_records([record], schema)
        by_path = fields_by_path(fields)
        self.assertEqual(
            by_path["/custom/field"],
            {
                "path": "/custom/field",
                "categories": ["clinical"],
                "sources": ["schema"],
            },
        )
        self.assertEqual(
            by_path["/email"]["categories"], ["contact", "quasi_identifier"]
        )
        self.assertEqual(by_path["/email"]["sources"], ["schema", "field_name", "value"])

    def test_schema_missing_path_skipped(self):
        (fields,) = classify_records([{"a": 1}], {"/nope": "clinical"})
        self.assertEqual(fields, [])

    def test_category_and_field_ordering(self):
        record = {"b_phone": "13800138000", "a_email": "x@y.com"}
        (fields,) = classify_records([record])
        self.assertEqual([f["path"] for f in fields], ["/a_email", "/b_phone"])

    def test_deterministic_output(self):
        record = {"患者": {"年龄": 30, "电话": "13800138000"}}
        self.assertEqual(classify_records([record]), classify_records([record]))

    def test_unmatched_record_returns_empty_fields(self):
        (fields,) = classify_records([{"score": 1, "flag": True, "txt": ""}])
        self.assertEqual(fields, [])

    def test_invalid_schema(self):
        with self.assertRaises(SchemaError):
            classify_records([{}], {"bad-pointer": "clinical"})
        with self.assertRaises(SchemaError):
            classify_records([{}], {"/a": "not_a_category"})
        with self.assertRaises(SchemaError):
            classify_records([{}], {"/a": []})

    def test_schema_does_not_leak_between_calls(self):
        classify_records([{"x": 1}], {"/x": "clinical"})
        (fields,) = classify_records([{"x": 1}])
        self.assertEqual(fields, [])


if __name__ == "__main__":
    unittest.main()
