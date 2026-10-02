import unittest

from privacare.classifier import InvalidRequest, InvalidSchema
from privacare.service import Service

VALID_ID = "11010519491231002X"  # checksum-valid mainland ID
VALID_CARD = "4111111111111111"  # Luhn-valid card number


def classify(payload):
    return Service().classify(payload)


def fields_by_path(result):
    return {f["path"]: f for f in result["fields"]}


class FieldNameTest(unittest.TestCase):
    def test_chinese_and_english_names(self):
        [result] = classify(
            {
                "records": [
                    {
                        "姓名": "张三",
                        "patient_name": "张三",
                        "手机号码": "13800138000",
                        "email": "a@b.com",
                        "诊断": "高血压",
                        "diagnosis": "hypertension",
                        "银行卡号": "6222",
                        "age": 45,
                        "gender": "男",
                        "科室": "心内科",
                    }
                ]
            }
        )
        fields = fields_by_path(result)
        self.assertEqual(fields["/姓名"]["categories"], ["direct_identifier"])
        self.assertEqual(fields["/patient_name"]["categories"], ["direct_identifier"])
        self.assertEqual(fields["/手机号码"]["categories"], ["contact"])
        self.assertEqual(fields["/email"]["categories"], ["contact"])
        self.assertEqual(fields["/诊断"]["categories"], ["clinical"])
        self.assertEqual(fields["/diagnosis"]["categories"], ["clinical"])
        self.assertEqual(fields["/银行卡号"]["categories"], ["financial"])
        self.assertEqual(fields["/age"]["categories"], ["quasi_identifier"])
        self.assertEqual(fields["/gender"]["categories"], ["quasi_identifier"])
        self.assertEqual(fields["/科室"]["categories"], ["quasi_identifier"])
        for field in fields.values():
            self.assertIn("field_name", field["sources"])

    def test_short_keyword_no_false_positive(self):
        [result] = classify(
            {"records": [{"dosage": "5mg", "message": "hello", "stage": "1"}]}
        )
        self.assertEqual(result["fields"], [])


class ValueDetectionTest(unittest.TestCase):
    def test_format_values(self):
        [result] = classify(
            {
                "records": [
                    {
                        "a": "zhang.san@example.com",
                        "b": "13800138000",
                        "c": "010-62345678",
                        "d": "+8613800138000",
                        "e": VALID_ID,
                        "f": VALID_CARD,
                    }
                ]
            }
        )
        fields = fields_by_path(result)
        self.assertEqual(fields["/a"], {"path": "/a", "categories": ["contact"], "sources": ["value"]})
        self.assertEqual(fields["/b"]["categories"], ["contact"])
        self.assertEqual(fields["/c"]["categories"], ["contact"])
        self.assertEqual(fields["/d"]["categories"], ["contact"])
        self.assertEqual(fields["/e"]["categories"], ["direct_identifier"])
        self.assertEqual(fields["/f"]["categories"], ["financial"])

    def test_invalid_formats_not_flagged(self):
        [result] = classify(
            {
                "records": [
                    {
                        "a": "110105194912310021",  # bad ID checksum
                        "b": "4111111111111112",  # fails Luhn
                        "c": "not-an-email@",
                        "d": "12345",
                        "e": "",
                        "f": None,
                        "g": True,
                        "h": 42,
                        "i": 13800138000,
                    }
                ]
            }
        )
        self.assertEqual(result["fields"], [])


class StructureTest(unittest.TestCase):
    def test_nested_pointers_and_array_indices(self):
        [result] = classify(
            {
                "records": [
                    {
                        "patient": {"name": "张三"},
                        "phones": ["13800138000", "13900139000"],
                        "a/b": {"c~d": "x@y.com"},
                    }
                ]
            }
        )
        fields = fields_by_path(result)
        self.assertIn("/patient/name", fields)
        self.assertEqual(fields["/phones/0"]["categories"], ["contact"])
        self.assertEqual(fields["/phones/1"]["categories"], ["contact"])
        self.assertIn("/a~1b/c~0d", fields)

    def test_array_element_uses_parent_key_name(self):
        [result] = classify({"records": [{"emails": [{"addr": "not an email"}]}]})
        fields = fields_by_path(result)
        self.assertEqual(fields["/emails/0/addr"]["categories"], ["contact"])
        self.assertEqual(fields["/emails/0/addr"]["sources"], ["field_name"])

    def test_fields_sorted_by_path_and_stable(self):
        record = {"b": "x@y.com", "a": "13800138000", "c": {"aa": VALID_ID}}
        payload = {"records": [record]}
        first = classify(payload)
        second = classify(payload)
        self.assertEqual(first, second)
        paths = [f["path"] for f in first[0]["fields"]]
        self.assertEqual(paths, sorted(paths))

    def test_unmatched_record_returns_empty_fields(self):
        results = classify({"records": [{"foo": "bar"}, {"name": "x"}, {}]})
        self.assertEqual([r["index"] for r in results], [0, 1, 2])
        self.assertEqual(results[0]["fields"], [])
        self.assertEqual(results[2]["fields"], [])
        self.assertEqual(len(results[1]["fields"]), 1)


class SchemaTest(unittest.TestCase):
    def test_schema_merges_with_auto_detection(self):
        [result] = classify(
            {
                "records": [{"mrn": "ABC-1", "note": "x@y.com", "other": "plain"}],
                "schema": {"/note": "clinical", "/other": ["quasi_identifier", "clinical"]},
            }
        )
        fields = fields_by_path(result)
        self.assertEqual(fields["/mrn"]["sources"], ["field_name"])
        self.assertEqual(
            fields["/note"],
            {"path": "/note", "categories": ["contact", "clinical"], "sources": ["schema", "value"]},
        )
        self.assertEqual(fields["/other"]["categories"], ["clinical", "quasi_identifier"])
        self.assertEqual(fields["/other"]["sources"], ["schema"])

    def test_schema_pointer_with_escapes_and_arrays(self):
        [result] = classify(
            {
                "records": [{"a/b": 1, "items": [{"x": 2}]}],
                "schema": {"/a~1b": "financial", "/items/0/x": "clinical"},
            }
        )
        fields = fields_by_path(result)
        self.assertEqual(fields["/a~1b"]["categories"], ["financial"])
        self.assertEqual(fields["/items/0/x"]["categories"], ["clinical"])

    def test_schema_missing_path_is_skipped(self):
        [result] = classify({"records": [{"foo": "bar"}], "schema": {"/nope": "clinical"}})
        self.assertEqual(result["fields"], [])

    def test_schema_does_not_leak_across_requests(self):
        service = Service()
        service.classify({"records": [{"note": "hello"}], "schema": {"/note": "clinical"}})
        [result] = service.classify({"records": [{"note": "hello"}]})
        self.assertEqual(result["fields"], [])

    def test_invalid_schema(self):
        bad = [
            {"records": [{}], "schema": "clinical"},
            {"records": [{}], "schema": ["clinical"]},
            {"records": [{}], "schema": {"note": "clinical"}},
            {"records": [{}], "schema": {"/note": "unknown"}},
            {"records": [{}], "schema": {"/note": []}},
            {"records": [{}], "schema": {"/note": 3}},
            {"records": [{}], "schema": {"/a~2b": "clinical"}},
        ]
        for payload in bad:
            with self.subTest(payload=payload):
                with self.assertRaises(InvalidSchema):
                    classify(payload)


class RequestValidationTest(unittest.TestCase):
    def test_invalid_request(self):
        bad = [
            None,
            [],
            "x",
            {},
            {"records": None},
            {"records": []},
            {"records": "x"},
            {"records": [1]},
            {"records": [None]},
            {"records": [[]]},
        ]
        for payload in bad:
            with self.subTest(payload=payload):
                with self.assertRaises(InvalidRequest):
                    classify(payload)


if __name__ == "__main__":
    unittest.main()
