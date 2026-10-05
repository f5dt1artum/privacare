import json
import unittest
from datetime import datetime, timedelta, timezone

from privacare import (
    ConsentNotFoundError,
    ConsentRegistry,
    InvalidConsentError,
    InvalidConsentSnapshotError,
)

UTC = timezone.utc
CST = timezone(timedelta(hours=8))

FROM = "2026-01-01T00:00:00Z"
UNTIL = "2027-01-01T00:00:00Z"


def make_registry(**overrides):
    registry = ConsentRegistry()
    record = {
        "consent_id": "c-1",
        "subject_id": "subj-1",
        "purposes": ["treatment", "research"],
        "data_categories": ["clinical", "contact"],
        "valid_from": FROM,
        "valid_until": UNTIL,
    }
    record.update(overrides)
    registry.register(**record)
    return registry


def evaluate(registry, **overrides):
    request = {
        "subject_id": "subj-1",
        "purpose": "treatment",
        "data_categories": ["clinical"],
        "evaluated_at": "2026-06-01T00:00:00Z",
    }
    request.update(overrides)
    return registry.evaluate(**request)


class RegisterTest(unittest.TestCase):
    def test_register_returns_first_version(self):
        registry = make_registry()
        record = registry.query("c-1")
        self.assertEqual(record["consent_id"], "c-1")
        self.assertEqual(record["subject_id"], "subj-1")
        self.assertEqual(record["purposes"], {"treatment", "research"})
        self.assertEqual(record["data_categories"], {"clinical", "contact"})
        self.assertEqual(record["valid_from"], datetime(2026, 1, 1, tzinfo=UTC))
        self.assertEqual(record["valid_until"], datetime(2027, 1, 1, tzinfo=UTC))
        self.assertEqual(record["status"], "active")
        self.assertEqual(record["version"], 1)
        self.assertIsNone(record["revoked_at"])

    def test_register_without_valid_until(self):
        registry = ConsentRegistry()
        record = registry.register(
            consent_id="c-1",
            subject_id="subj-1",
            purposes=["treatment"],
            data_categories=["clinical"],
            valid_from=FROM,
        )
        self.assertIsNone(record["valid_until"])

    def test_register_accepts_mapping_and_datetimes(self):
        registry = ConsentRegistry()
        record = registry.register(
            {
                "consent_id": "c-1",
                "subject_id": "subj-1",
                "purposes": {"treatment"},
                "data_categories": {"clinical"},
                "valid_from": datetime(2026, 1, 1, tzinfo=CST),
            }
        )
        self.assertEqual(record["valid_from"], datetime(2026, 1, 1, tzinfo=CST))

    def test_identical_reregister_is_idempotent(self):
        registry = make_registry()
        again = registry.register(
            consent_id="c-1",
            subject_id="subj-1",
            purposes=["research", "treatment"],
            data_categories=["contact", "clinical"],
            valid_from="2026-01-01T08:00:00+08:00",  # 与 FROM 同一时刻
            valid_until="2027-01-01T08:00:00+08:00",
        )
        self.assertEqual(again["version"], 1)
        self.assertEqual(len(registry.history("c-1")), 1)

    def test_changed_content_creates_new_version_and_keeps_history(self):
        registry = make_registry()
        updated = registry.register(
            consent_id="c-1",
            subject_id="subj-1",
            purposes=["treatment"],
            data_categories=["clinical"],
            valid_from=FROM,
            valid_until=UNTIL,
        )
        self.assertEqual(updated["version"], 2)
        history = registry.history("c-1")
        self.assertEqual([v["version"] for v in history], [1, 2])
        self.assertEqual(history[0]["purposes"], {"treatment", "research"})
        self.assertEqual(history[1]["purposes"], {"treatment"})
        self.assertEqual(registry.query("c-1")["purposes"], {"treatment"})

    def test_update_requires_existing_consent(self):
        registry = ConsentRegistry()
        with self.assertRaises(ConsentNotFoundError):
            registry.update(
                consent_id="missing",
                subject_id="subj-1",
                purposes=["treatment"],
                data_categories=["clinical"],
                valid_from=FROM,
            )

    def test_update_changes_content(self):
        registry = make_registry()
        updated = registry.update(
            consent_id="c-1",
            subject_id="subj-1",
            purposes=["treatment", "research"],
            data_categories=["clinical", "contact"],
            valid_from=FROM,
            valid_until="2028-01-01T00:00:00Z",
        )
        self.assertEqual(updated["version"], 2)
        self.assertEqual(updated["valid_until"], datetime(2028, 1, 1, tzinfo=UTC))

    def test_register_after_revoke_reactivates_with_new_version(self):
        registry = make_registry()
        registry.revoke("c-1", "2026-06-01T00:00:00Z")
        record = registry.register(
            consent_id="c-1",
            subject_id="subj-1",
            purposes=["treatment", "research"],
            data_categories=["clinical", "contact"],
            valid_from=FROM,
            valid_until=UNTIL,
        )
        self.assertEqual(record["version"], 3)
        self.assertEqual(record["status"], "active")


class ValidationTest(unittest.TestCase):
    def register_bad(self, **overrides):
        registry = ConsentRegistry()
        record = {
            "consent_id": "c-1",
            "subject_id": "subj-1",
            "purposes": ["treatment"],
            "data_categories": ["clinical"],
            "valid_from": FROM,
        }
        record.update(overrides)
        registry.register(**record)

    def test_missing_required_field(self):
        registry = ConsentRegistry()
        with self.assertRaises(InvalidConsentError):
            registry.register(
                consent_id="c-1",
                subject_id="subj-1",
                purposes=["treatment"],
                valid_from=FROM,
            )

    def test_empty_identifiers(self):
        with self.assertRaises(InvalidConsentError):
            self.register_bad(consent_id="")
        with self.assertRaises(InvalidConsentError):
            self.register_bad(subject_id="")

    def test_empty_sets(self):
        with self.assertRaises(InvalidConsentError):
            self.register_bad(purposes=[])
        with self.assertRaises(InvalidConsentError):
            self.register_bad(data_categories=set())

    def test_non_string_set_items(self):
        with self.assertRaises(InvalidConsentError):
            self.register_bad(purposes=["treatment", 1])
        with self.assertRaises(InvalidConsentError):
            self.register_bad(data_categories="clinical")

    def test_naive_time_rejected(self):
        with self.assertRaises(InvalidConsentError):
            self.register_bad(valid_from="2026-01-01T00:00:00")
        with self.assertRaises(InvalidConsentError):
            self.register_bad(valid_from=datetime(2026, 1, 1))
        with self.assertRaises(InvalidConsentError):
            self.register_bad(valid_until="2027-01-01")

    def test_valid_until_must_be_later_than_valid_from(self):
        with self.assertRaises(InvalidConsentError):
            self.register_bad(valid_until=FROM)
        with self.assertRaises(InvalidConsentError):
            self.register_bad(valid_until="2025-12-31T23:59:59Z")

    def test_equivalent_instants_compare_equal(self):
        registry = ConsentRegistry()
        registry.register(
            consent_id="c-1",
            subject_id="subj-1",
            purposes=["treatment"],
            data_categories=["clinical"],
            valid_from="2026-01-01T08:00:00+08:00",
            valid_until="2027-01-01T00:00:00Z",
        )
        # 2027-01-01T08:00:00+08:00 与 valid_until 同一时刻,视为已失效。
        result = evaluate(registry, evaluated_at="2027-01-01T08:00:00+08:00")
        self.assertEqual(result["reason"], "EXPIRED")


class RevokeTest(unittest.TestCase):
    def test_revoke_creates_new_version(self):
        registry = make_registry()
        record = registry.revoke("c-1", "2026-06-01T00:00:00Z")
        self.assertEqual(record["version"], 2)
        self.assertEqual(record["status"], "revoked")
        self.assertEqual(record["revoked_at"], datetime(2026, 6, 1, tzinfo=UTC))
        history = registry.history("c-1")
        self.assertEqual([v["status"] for v in history], ["active", "revoked"])
        self.assertIsNone(history[0]["revoked_at"])

    def test_revoke_unknown_consent(self):
        registry = ConsentRegistry()
        with self.assertRaises(ConsentNotFoundError):
            registry.revoke("missing", "2026-06-01T00:00:00Z")

    def test_revoke_before_valid_from(self):
        registry = make_registry()
        with self.assertRaises(InvalidConsentError):
            registry.revoke("c-1", "2025-12-31T23:59:59Z")

    def test_revoke_at_valid_from_is_allowed(self):
        registry = make_registry()
        record = registry.revoke("c-1", FROM)
        self.assertEqual(record["status"], "revoked")

    def test_revoke_idempotent_for_same_instant(self):
        registry = make_registry()
        registry.revoke("c-1", "2026-06-01T00:00:00Z")
        again = registry.revoke("c-1", "2026-06-01T08:00:00+08:00")
        self.assertEqual(again["version"], 2)
        self.assertEqual(len(registry.history("c-1")), 2)

    def test_revoke_twice_with_different_time(self):
        registry = make_registry()
        registry.revoke("c-1", "2026-06-01T00:00:00Z")
        with self.assertRaises(InvalidConsentError):
            registry.revoke("c-1", "2026-07-01T00:00:00Z")


class QueryTest(unittest.TestCase):
    def test_query_unknown_consent(self):
        registry = ConsentRegistry()
        with self.assertRaises(ConsentNotFoundError):
            registry.query("missing")
        with self.assertRaises(ConsentNotFoundError):
            registry.history("missing")

    def test_history_is_ascending_and_isolated(self):
        registry = make_registry()
        registry.revoke("c-1", "2026-06-01T00:00:00Z")
        history = registry.history("c-1")
        self.assertIsInstance(history, tuple)
        self.assertEqual([v["version"] for v in history], [1, 2])
        history[0]["purposes"] = set()
        history[0]["status"] = "revoked"
        self.assertEqual(registry.history("c-1")[0]["purposes"], {"treatment", "research"})
        self.assertEqual(registry.history("c-1")[0]["status"], "active")

    def test_query_result_is_isolated(self):
        registry = make_registry()
        record = registry.query("c-1")
        record["subject_id"] = "tampered"
        self.assertEqual(registry.query("c-1")["subject_id"], "subj-1")


class EvaluateTest(unittest.TestCase):
    def test_allow(self):
        registry = make_registry()
        result = evaluate(registry)
        self.assertEqual(
            result,
            {"decision": "ALLOW", "reason": "ALLOWED", "consent_id": "c-1", "version": 1},
        )

    def test_allow_requires_all_categories_on_one_record(self):
        registry = ConsentRegistry()
        registry.register(
            consent_id="c-1",
            subject_id="subj-1",
            purposes=["treatment"],
            data_categories=["clinical"],
            valid_from=FROM,
        )
        registry.register(
            consent_id="c-2",
            subject_id="subj-1",
            purposes=["treatment"],
            data_categories=["contact"],
            valid_from=FROM,
        )
        result = evaluate(registry, data_categories=["clinical", "contact"])
        self.assertEqual(result["decision"], "DENY")
        self.assertEqual(result["reason"], "DATA_CATEGORY_NOT_ALLOWED")

    def test_no_consent(self):
        registry = make_registry()
        result = evaluate(registry, subject_id="subj-2")
        self.assertEqual(
            result,
            {"decision": "DENY", "reason": "NO_CONSENT", "consent_id": None, "version": None},
        )

    def test_not_yet_effective(self):
        registry = make_registry()
        result = evaluate(registry, evaluated_at="2025-12-31T23:59:59Z")
        self.assertEqual(result["reason"], "NOT_YET_EFFECTIVE")

    def test_valid_from_boundary_is_effective(self):
        registry = make_registry()
        result = evaluate(registry, evaluated_at=FROM)
        self.assertEqual(result["decision"], "ALLOW")

    def test_valid_until_boundary_is_expired(self):
        registry = make_registry()
        result = evaluate(registry, evaluated_at=UNTIL)
        self.assertEqual(result["reason"], "EXPIRED")

    def test_no_expiry_never_expires(self):
        registry = make_registry(valid_until=None)
        result = evaluate(registry, evaluated_at="2099-01-01T00:00:00Z")
        self.assertEqual(result["decision"], "ALLOW")

    def test_revoked(self):
        registry = make_registry()
        registry.revoke("c-1", "2026-03-01T00:00:00Z")
        result = evaluate(registry, evaluated_at="2026-06-01T00:00:00Z")
        self.assertEqual(result["reason"], "REVOKED")
        self.assertIsNone(result["consent_id"])

    def test_revocation_takes_effect_at_revoked_at(self):
        registry = make_registry()
        registry.revoke("c-1", "2026-06-01T00:00:00Z")
        before = evaluate(registry, evaluated_at="2026-05-31T23:59:59Z")
        self.assertEqual(before["decision"], "ALLOW")
        at = evaluate(registry, evaluated_at="2026-06-01T00:00:00Z")
        self.assertEqual(at["reason"], "REVOKED")

    def test_purpose_not_allowed(self):
        registry = make_registry()
        result = evaluate(registry, purpose="marketing")
        self.assertEqual(result["reason"], "PURPOSE_NOT_ALLOWED")

    def test_data_category_not_allowed(self):
        registry = make_registry()
        result = evaluate(registry, data_categories=["clinical", "financial"])
        self.assertEqual(result["reason"], "DATA_CATEGORY_NOT_ALLOWED")

    def test_reason_priority(self):
        registry = ConsentRegistry()
        registry.register(
            consent_id="c-revoked",
            subject_id="subj-1",
            purposes=["treatment"],
            data_categories=["clinical"],
            valid_from=FROM,
        )
        registry.revoke("c-revoked", "2026-03-01T00:00:00Z")
        registry.register(
            consent_id="c-expired",
            subject_id="subj-1",
            purposes=["treatment"],
            data_categories=["clinical"],
            valid_from=FROM,
            valid_until="2026-04-01T00:00:00Z",
        )
        registry.register(
            consent_id="c-scope",
            subject_id="subj-1",
            purposes=["billing"],
            data_categories=["contact"],
            valid_from=FROM,
        )
        # REVOKED 优先于 EXPIRED、PURPOSE、DATA_CATEGORY。
        self.assertEqual(evaluate(registry)["reason"], "REVOKED")
        registry2 = ConsentRegistry()
        registry2.register(
            consent_id="c-expired",
            subject_id="subj-1",
            purposes=["treatment"],
            data_categories=["clinical"],
            valid_from=FROM,
            valid_until="2026-04-01T00:00:00Z",
        )
        registry2.register(
            consent_id="c-scope",
            subject_id="subj-1",
            purposes=["billing"],
            data_categories=["contact"],
            valid_from=FROM,
        )
        # EXPIRED 优先于 PURPOSE_NOT_ALLOWED。
        self.assertEqual(evaluate(registry2)["reason"], "EXPIRED")

    def test_latest_version_governs(self):
        registry = make_registry()
        registry.register(
            consent_id="c-1",
            subject_id="subj-1",
            purposes=["research"],
            data_categories=["clinical"],
            valid_from=FROM,
            valid_until=UNTIL,
        )
        self.assertEqual(evaluate(registry)["reason"], "PURPOSE_NOT_ALLOWED")
        self.assertEqual(evaluate(registry, purpose="research")["decision"], "ALLOW")

    def test_allow_reports_latest_version(self):
        registry = make_registry()
        registry.register(
            consent_id="c-1",
            subject_id="subj-1",
            purposes=["treatment", "research"],
            data_categories=["clinical", "contact"],
            valid_from=FROM,
            valid_until="2028-01-01T00:00:00Z",
        )
        result = evaluate(registry)
        self.assertEqual(result["version"], 2)

    def test_evaluate_rejects_bad_input(self):
        registry = make_registry()
        with self.assertRaises(InvalidConsentError):
            evaluate(registry, data_categories=[])
        with self.assertRaises(InvalidConsentError):
            evaluate(registry, evaluated_at="2026-06-01T00:00:00")
        with self.assertRaises(InvalidConsentError):
            evaluate(registry, purpose="")


class SnapshotTest(unittest.TestCase):
    def build_registry(self):
        registry = ConsentRegistry()
        registry.register(
            consent_id="c-2",
            subject_id="subj-2",
            purposes=["research"],
            data_categories=["clinical"],
            valid_from=FROM,
        )
        registry.register(
            consent_id="c-1",
            subject_id="subj-1",
            purposes=["treatment"],
            data_categories=["clinical", "contact"],
            valid_from=FROM,
            valid_until=UNTIL,
        )
        registry.register(
            consent_id="c-1",
            subject_id="subj-1",
            purposes=["treatment", "billing"],
            data_categories=["clinical", "contact"],
            valid_from=FROM,
            valid_until=UNTIL,
        )
        registry.revoke("c-1", "2026-06-01T00:00:00Z")
        return registry

    def test_export_is_deterministic(self):
        registry = self.build_registry()
        self.assertEqual(registry.export_snapshot(), registry.export_snapshot())
        # 以不同顺序重建相同状态,字节仍一致。
        other = ConsentRegistry()
        other.register(
            consent_id="c-1",
            subject_id="subj-1",
            purposes=["treatment"],
            data_categories=["clinical", "contact"],
            valid_from=FROM,
            valid_until=UNTIL,
        )
        other.register(
            consent_id="c-2",
            subject_id="subj-2",
            purposes=["research"],
            data_categories=["clinical"],
            valid_from=FROM,
        )
        other.register(
            consent_id="c-1",
            subject_id="subj-1",
            purposes=["treatment", "billing"],
            data_categories=["clinical", "contact"],
            valid_from=FROM,
            valid_until=UNTIL,
        )
        other.revoke("c-1", "2026-06-01T00:00:00Z")
        self.assertEqual(registry.export_snapshot(), other.export_snapshot())

    def test_round_trip_restores_everything(self):
        registry = self.build_registry()
        snapshot = registry.export_snapshot()
        restored = ConsentRegistry.from_snapshot(snapshot)
        self.assertEqual(restored.export_snapshot(), snapshot)
        self.assertEqual(restored.history("c-1"), registry.history("c-1"))
        revoked = restored.query("c-1")
        self.assertEqual(revoked["status"], "revoked")
        self.assertEqual(revoked["revoked_at"], datetime(2026, 6, 1, tzinfo=UTC))
        self.assertEqual(revoked["version"], 3)
        # 恢复后继续递增版本。
        record = restored.register(
            consent_id="c-1",
            subject_id="subj-1",
            purposes=["treatment"],
            data_categories=["clinical"],
            valid_from=FROM,
        )
        self.assertEqual(record["version"], 4)

    def test_import_accepts_str_bytes_and_object(self):
        registry = self.build_registry()
        snapshot = registry.export_snapshot()
        for payload in (snapshot, snapshot.encode("utf-8"), json.loads(snapshot)):
            restored = ConsentRegistry.from_snapshot(payload)
            self.assertEqual(restored.export_snapshot(), snapshot)

    def test_failed_import_leaves_no_partial_data(self):
        registry = self.build_registry()
        before = registry.export_snapshot()
        payload = json.loads(before)
        payload["consents"][0]["versions"][0]["version"] = 9
        with self.assertRaises(InvalidConsentSnapshotError):
            registry.import_snapshot(json.dumps(payload))
        self.assertEqual(registry.export_snapshot(), before)

    def test_bad_snapshots(self):
        registry = self.build_registry()
        good = json.loads(registry.export_snapshot())

        def broken(mutate):
            payload = json.loads(registry.export_snapshot())
            mutate(payload)
            return json.dumps(payload)

        bad_payloads = [
            "not json",
            "[]",
            broken(lambda p: p.update(format="other")),
            broken(lambda p: p.update(version=2)),
            broken(lambda p: p.update(consents={})),
            broken(lambda p: p["consents"].append(p["consents"][0])),
            broken(lambda p: p["consents"][0].update(versions=[])),
            broken(lambda p: p["consents"][0]["versions"][0].update(version=7)),
            broken(lambda p: p["consents"][0]["versions"][0].update(purposes=[])),
            broken(lambda p: p["consents"][0]["versions"][0].update(valid_from="2026-01-01")),
            broken(lambda p: p["consents"][0]["versions"][0].update(valid_until=FROM)),
            broken(lambda p: p["consents"][0]["versions"][0].update(status="unknown")),
            broken(lambda p: p["consents"][0]["versions"][0].update(revoked_at="2026-01-02T00:00:00Z")),
            broken(lambda p: p["consents"][0]["versions"][-1].update(revoked_at=None)),
            broken(
                lambda p: p["consents"][0]["versions"][-1].update(
                    revoked_at="2025-12-31T00:00:00Z"
                )
            ),
        ]
        for payload in bad_payloads:
            with self.assertRaises(InvalidConsentSnapshotError, msg=payload):
                ConsentRegistry.from_snapshot(payload)
        # 校验良好的快照作为对照。
        self.assertEqual(
            ConsentRegistry.from_snapshot(json.dumps(good)).export_snapshot(),
            registry.export_snapshot(),
        )


class PublicEntryTest(unittest.TestCase):
    def test_package_exports(self):
        import privacare

        self.assertIs(privacare.ConsentRegistry, ConsentRegistry)
        self.assertIs(privacare.InvalidConsentError, InvalidConsentError)
        self.assertIs(privacare.ConsentNotFoundError, ConsentNotFoundError)
        self.assertIs(privacare.InvalidConsentSnapshotError, InvalidConsentSnapshotError)

    def test_existing_modules_unaffected(self):
        from privacare.consent import consent_evaluate_request

        payload = {
            "consents": [
                {
                    "consent_id": "c-1",
                    "subject_id": "subj-1",
                    "purposes": ["treatment"],
                    "data_categories": ["clinical"],
                    "recipients": ["hospital-a"],
                    "valid_from": FROM,
                    "valid_until": UNTIL,
                    "status": "active",
                }
            ],
            "accesses": [
                {
                    "subject_id": "subj-1",
                    "purpose": "treatment",
                    "data_category": "clinical",
                    "recipient": "hospital-a",
                    "requested_at": "2026-06-01T00:00:00Z",
                }
            ],
        }
        results = consent_evaluate_request(payload)
        self.assertEqual(results[0]["reason"], "consent_granted")


if __name__ == "__main__":
    unittest.main()
