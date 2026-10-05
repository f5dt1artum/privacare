import json
import unittest
from dataclasses import FrozenInstanceError
from datetime import datetime, timezone

from privacare import (
    ALLOW,
    DENY,
    ConsentNotFoundError,
    ConsentRegistry,
    InvalidConsentError,
    InvalidConsentSnapshotError,
    __version__,
)


def make_registry():
    registry = ConsentRegistry()
    registry.register(
        "c-1",
        "subj-1",
        data_categories=["clinical", "contact"],
        purposes=["treatment"],
        effective_from="2026-01-01T00:00:00Z",
        expires_at="2026-12-31T23:59:59Z",
    )
    return registry


class RegisterTest(unittest.TestCase):
    def test_register_returns_first_version(self):
        record = make_registry().get("c-1")
        self.assertEqual(record.version, 1)
        self.assertEqual(record.status, "active")
        self.assertIsNone(record.revoked_at)
        self.assertEqual(record.data_categories, frozenset({"clinical", "contact"}))
        self.assertEqual(record.purposes, frozenset({"treatment"}))

    def test_identical_reregister_is_idempotent(self):
        registry = make_registry()
        again = registry.register(
            "c-1",
            "subj-1",
            data_categories={"contact", "clinical"},
            purposes=["treatment"],
            effective_from="2026-01-01T00:00:00+00:00",
            expires_at="2026-12-31T23:59:59Z",
        )
        self.assertEqual(again.version, 1)
        self.assertEqual(len(registry.history("c-1")), 1)

    def test_changed_content_creates_incrementing_version(self):
        registry = make_registry()
        updated = registry.register(
            "c-1",
            "subj-1",
            data_categories=["clinical"],
            purposes=["treatment", "research"],
            effective_from="2026-01-01T00:00:00Z",
            expires_at="2026-12-31T23:59:59Z",
        )
        self.assertEqual(updated.version, 2)
        history = registry.history("c-1")
        self.assertEqual([r.version for r in history], [1, 2])
        self.assertEqual(history[0].purposes, frozenset({"treatment"}))
        self.assertEqual(registry.get("c-1").purposes, updated.purposes)

    def test_update_requires_existing_consent(self):
        with self.assertRaises(ConsentNotFoundError):
            ConsentRegistry().update(
                "nope", "s", ["clinical"], ["treatment"], "2026-01-01T00:00:00Z"
            )

    def test_register_accepts_aware_datetimes(self):
        registry = ConsentRegistry()
        record = registry.register(
            "c-9",
            "subj-9",
            data_categories=["clinical"],
            purposes=["treatment"],
            effective_from=datetime(2026, 1, 1, tzinfo=timezone.utc),
        )
        self.assertIsNone(record.expires_at)

    def test_register_rejects_bad_fields(self):
        registry = ConsentRegistry()
        base = dict(
            subject_id="subj-1",
            data_categories=["clinical"],
            purposes=["treatment"],
            effective_from="2026-01-01T00:00:00Z",
        )
        with self.assertRaises(InvalidConsentError):
            registry.register("", **base)
        with self.assertRaises(InvalidConsentError):
            registry.register("c-1", **{**base, "subject_id": ""})
        with self.assertRaises(InvalidConsentError):
            registry.register("c-1", **{**base, "data_categories": []})
        with self.assertRaises(InvalidConsentError):
            registry.register("c-1", **{**base, "purposes": []})
        with self.assertRaises(InvalidConsentError):
            registry.register("c-1", **{**base, "effective_from": "2026-01-01T00:00:00"})
        with self.assertRaises(InvalidConsentError):
            registry.register(
                "c-1",
                **{**base, "effective_from": datetime(2026, 1, 1)},
            )
        with self.assertRaises(InvalidConsentError):
            registry.register(
                "c-1", **{**base, "expires_at": "2026-01-01T00:00:00Z"}
            )
        with self.assertRaises(InvalidConsentError):
            registry.register(
                "c-1", **{**base, "expires_at": "2025-12-31T23:59:59Z"}
            )


class RevokeTest(unittest.TestCase):
    def test_revoke_creates_new_version_and_keeps_history(self):
        registry = make_registry()
        revoked = registry.revoke("c-1", "2026-06-01T00:00:00Z")
        self.assertEqual(revoked.version, 2)
        self.assertEqual(revoked.status, "revoked")
        history = registry.history("c-1")
        self.assertEqual([r.status for r in history], ["active", "revoked"])
        self.assertEqual(history[0].version, 1)

    def test_revoke_is_idempotent_for_same_moment(self):
        registry = make_registry()
        registry.revoke("c-1", "2026-06-01T00:00:00Z")
        again = registry.revoke("c-1", "2026-06-01T00:00:00Z")
        self.assertEqual(again.version, 2)
        self.assertEqual(len(registry.history("c-1")), 2)

    def test_revoke_unknown_or_invalid(self):
        registry = make_registry()
        with self.assertRaises(ConsentNotFoundError):
            registry.revoke("nope", "2026-06-01T00:00:00Z")
        with self.assertRaises(InvalidConsentError):
            registry.revoke("c-1", "2025-12-31T23:59:59Z")
        with self.assertRaises(InvalidConsentError):
            registry.revoke("c-1", "2026-06-01T00:00:00")
        registry.revoke("c-1", "2026-06-01T00:00:00Z")
        with self.assertRaises(InvalidConsentError):
            registry.revoke("c-1", "2026-07-01T00:00:00Z")

    def test_get_and_history_unknown_consent(self):
        registry = make_registry()
        with self.assertRaises(ConsentNotFoundError):
            registry.get("nope")
        with self.assertRaises(ConsentNotFoundError):
            registry.history("nope")

    def test_history_is_immutable_for_caller(self):
        registry = make_registry()
        registry.revoke("c-1", "2026-06-01T00:00:00Z")
        history = registry.history("c-1")
        self.assertIsInstance(history, tuple)
        record = history[0]
        with self.assertRaises(FrozenInstanceError):
            record.status = "revoked"
        with self.assertRaises(AttributeError):
            record.purposes.add("research")
        self.assertEqual(registry.get("c-1").version, 2)


class EvaluateTest(unittest.TestCase):
    def evaluate(self, registry, **overrides):
        query = {
            "subject_id": "subj-1",
            "purpose": "treatment",
            "data_categories": ["clinical"],
            "evaluated_at": "2026-06-01T12:00:00Z",
        }
        query.update(overrides)
        return registry.evaluate(**query)

    def test_allow_reports_hit(self):
        decision = self.evaluate(make_registry())
        self.assertEqual(decision.decision, ALLOW)
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.consent_id, "c-1")
        self.assertEqual(decision.version, 1)

    def test_no_consent(self):
        decision = self.evaluate(make_registry(), subject_id="ghost")
        self.assertEqual((decision.decision, decision.reason), (DENY, "NO_CONSENT"))
        self.assertIsNone(decision.consent_id)
        self.assertIsNone(decision.version)

    def test_not_yet_effective(self):
        decision = self.evaluate(make_registry(), evaluated_at="2025-12-31T23:59:59Z")
        self.assertEqual(decision.reason, "NOT_YET_EFFECTIVE")

    def test_effective_from_boundary_is_effective(self):
        decision = self.evaluate(make_registry(), evaluated_at="2026-01-01T00:00:00Z")
        self.assertEqual(decision.decision, ALLOW)

    def test_expires_at_boundary_is_expired(self):
        decision = self.evaluate(make_registry(), evaluated_at="2026-12-31T23:59:59Z")
        self.assertEqual(decision.reason, "EXPIRED")

    def test_revoked(self):
        registry = make_registry()
        registry.revoke("c-1", "2026-06-01T00:00:00Z")
        self.assertEqual(self.evaluate(registry).reason, "REVOKED")
        # 撤销自撤销时间起生效，之前仍然有效。
        before = self.evaluate(registry, evaluated_at="2026-05-31T23:59:59Z")
        self.assertEqual(before.decision, ALLOW)
        at = self.evaluate(registry, evaluated_at="2026-06-01T00:00:00Z")
        self.assertEqual(at.reason, "REVOKED")

    def test_purpose_not_allowed(self):
        decision = self.evaluate(make_registry(), purpose="marketing")
        self.assertEqual(decision.reason, "PURPOSE_NOT_ALLOWED")

    def test_data_category_not_allowed(self):
        decision = self.evaluate(make_registry(), data_categories=["clinical", "financial"])
        self.assertEqual(decision.reason, "DATA_CATEGORY_NOT_ALLOWED")

    def test_reason_priority_revoked_over_expired(self):
        registry = make_registry()
        registry.register(
            "c-2",
            "subj-1",
            data_categories=["clinical"],
            purposes=["treatment"],
            effective_from="2026-01-01T00:00:00Z",
            expires_at="2026-02-01T00:00:00Z",
        )
        registry.revoke("c-1", "2026-03-01T00:00:00Z")
        decision = self.evaluate(registry, evaluated_at="2026-06-01T00:00:00Z")
        self.assertEqual(decision.reason, "REVOKED")

    def test_reason_priority_purpose_over_category(self):
        registry = make_registry()
        registry.register(
            "c-2",
            "subj-1",
            data_categories=["clinical"],
            purposes=["treatment"],
            effective_from="2026-01-01T00:00:00Z",
        )
        decision = self.evaluate(
            registry, purpose="marketing", data_categories=["financial"]
        )
        self.assertEqual(decision.reason, "PURPOSE_NOT_ALLOWED")

    def test_not_yet_effective_only_when_none_effective(self):
        registry = make_registry()
        registry.register(
            "c-2",
            "subj-1",
            data_categories=["clinical"],
            purposes=["treatment"],
            effective_from="2027-01-01T00:00:00Z",
        )
        self.assertEqual(self.evaluate(registry).decision, ALLOW)

    def test_evaluate_rejects_bad_request(self):
        registry = make_registry()
        with self.assertRaises(InvalidConsentError):
            registry.evaluate("subj-1", "treatment", [], "2026-06-01T00:00:00Z")
        with self.assertRaises(InvalidConsentError):
            registry.evaluate("subj-1", "treatment", ["clinical"], "2026-06-01")


class SnapshotTest(unittest.TestCase):
    def build(self):
        registry = make_registry()
        registry.register(
            "c-1",
            "subj-1",
            data_categories=["clinical", "contact", "financial"],
            purposes=["treatment", "research"],
            effective_from="2026-02-01T00:00:00+01:00",
            expires_at="2026-12-31T23:59:59Z",
        )
        registry.revoke("c-1", "2026-06-01T00:00:00Z")
        registry.register(
            "c-2",
            "subj-2",
            data_categories=["clinical"],
            purposes=["treatment"],
            effective_from="2026-01-01T00:00:00Z",
        )
        return registry

    def test_export_is_deterministic(self):
        registry = self.build()
        first = registry.export_snapshot()
        second = registry.export_snapshot()
        self.assertEqual(first, second)
        self.assertEqual(first.encode("utf-8"), second.encode("utf-8"))
        json.loads(first)

    def test_round_trip_restores_everything(self):
        registry = self.build()
        restored = ConsentRegistry.import_snapshot(registry.export_snapshot())
        self.assertEqual(restored.export_snapshot(), registry.export_snapshot())
        self.assertEqual(restored.history("c-1"), registry.history("c-1"))
        revoked = restored.get("c-1")
        self.assertEqual(revoked.status, "revoked")
        self.assertEqual(revoked.version, 3)
        self.assertEqual(
            revoked.revoked_at, datetime(2026, 6, 1, tzinfo=timezone.utc)
        )
        decision = restored.evaluate(
            "subj-2", "treatment", ["clinical"], "2026-06-01T12:00:00Z"
        )
        self.assertEqual((decision.decision, decision.consent_id), (ALLOW, "c-2"))

    def test_failed_import_leaves_no_partial_data(self):
        registry = self.build()
        before = registry.export_snapshot()
        snapshot = json.loads(before)
        snapshot["consents"][0]["versions"][0]["version"] = 7
        with self.assertRaises(InvalidConsentSnapshotError):
            registry.load_snapshot(json.dumps(snapshot))
        self.assertEqual(registry.export_snapshot(), before)

    def test_invalid_snapshots(self):
        registry = self.build()
        valid = json.loads(registry.export_snapshot())
        bad_payloads = [
            "not json",
            json.dumps([]),
            json.dumps({**valid, "format": "other"}),
            json.dumps({**valid, "version": 2}),
            json.dumps({**valid, "consents": {}}),
        ]
        dup = dict(valid)
        dup["consents"] = valid["consents"] + valid["consents"][:1]
        bad_payloads.append(json.dumps(dup))
        missing = dict(valid)
        missing["consents"] = [
            {**valid["consents"][0], "versions": [{"version": 1}]}
        ]
        bad_payloads.append(json.dumps(missing))
        naive = json.loads(registry.export_snapshot())
        naive["consents"][0]["versions"][0]["effective_from"] = "2026-01-01T00:00:00"
        bad_payloads.append(json.dumps(naive))
        bad_revoke = json.loads(registry.export_snapshot())
        bad_revoke["consents"][0]["versions"][-1]["revoked_at"] = None
        bad_payloads.append(json.dumps(bad_revoke))
        for payload in bad_payloads:
            with self.assertRaises(InvalidConsentSnapshotError, msg=payload):
                ConsentRegistry.import_snapshot(payload)


class PublicSurfaceTest(unittest.TestCase):
    def test_package_entry_exports(self):
        import privacare

        self.assertIs(privacare.ConsentRegistry, ConsentRegistry)
        self.assertEqual(privacare.__version__, __version__)

    def test_existing_modules_untouched(self):
        from privacare.service import Service

        self.assertEqual(Service().health()["status"], "ok")


if __name__ == "__main__":
    unittest.main()
