#!/usr/bin/env python3
"""Tests for OCD entity reconciliation collision classes."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SCRIPTS = ROOT.parent / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from ocd_entity_reconciler import OcdEntityReconciler, load_yaml  # noqa: E402


class OcdReconcilerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.fixtures = ROOT / "fixtures"
        cls.overrides = ROOT / "mapping_overrides.yml"
        cls.reconciler = OcdEntityReconciler.from_paths(
            actors_dir=cls.fixtures / "actors",
            malware_dir=cls.fixtures / "malware",
            overrides_path=cls.overrides,
            map_version=29,
            source_snapshot_id="ocd:snapshot:v29:fixture",
        )
        labels_doc = load_yaml(cls.fixtures / "ocd_labels.yml")
        cls.by_name = {
            r.label_raw: r
            for r in cls.reconciler.reconcile_all(labels_doc["labels"])
        }

    def test_exact_lockbit_accepted_no_merge(self) -> None:
        r = self.by_name["LockBit"]
        self.assertEqual(r.review_status, "accepted")
        self.assertEqual(r.confidence, "high")
        self.assertFalse(r.auto_merge)
        self.assertTrue(r.auto_attach_provenance)
        slugs = {c.slug for c in r.candidates if c.ref_kind == "canonical_actor"}
        self.assertIn("lockbit", slugs)
        self.assertNotIn("lockbit-ransomware-actors-affiliates", slugs)

    def test_lockbit_version_needs_review_not_merged(self) -> None:
        for label in ("LockBit 3.0", "LockBit 2.0"):
            r = self.by_name[label]
            self.assertEqual(r.match_kind, "family_variant", label)
            self.assertEqual(r.review_status, "needs_review", label)
            self.assertFalse(r.auto_merge, label)
            self.assertFalse(r.auto_attach_provenance, label)
            kinds = {c.ref_kind for c in r.candidates}
            self.assertTrue(
                "canonical_actor" in kinds or "canonical_malware" in kinds,
                label,
            )
            self.assertIn("family_variant", r.collision_flags, label)

    def test_lockbit_green_override_review(self) -> None:
        r = self.by_name["LockBit Green"]
        self.assertEqual(r.review_status, "needs_review")
        self.assertFalse(r.auto_merge)
        self.assertEqual(r.match_kind, "override_review")

    def test_conti_exact_accepted(self) -> None:
        r = self.by_name["Conti"]
        self.assertEqual(r.review_status, "accepted")
        self.assertEqual(r.candidates[0].slug, "conti")
        self.assertFalse(r.auto_merge)

    def test_wizard_spider_ambiguous_conti_cluster(self) -> None:
        r = self.by_name["Wizard Spider"]
        self.assertEqual(r.review_status, "needs_review")
        self.assertEqual(r.match_kind, "ambiguous")
        self.assertFalse(r.auto_merge)
        slugs = {c.slug for c in r.candidates if c.ref_kind == "canonical_actor"}
        self.assertTrue({"conti", "wizard-spider", "ryuk"} & slugs)
        self.assertGreaterEqual(len(slugs), 2)

    def test_ryuk_actor_malware_and_alias_collision(self) -> None:
        r = self.by_name["Ryuk"]
        self.assertEqual(r.review_status, "needs_review")
        self.assertFalse(r.auto_merge)
        # multi-actor (Conti alias + Ryuk page) and/or malware overlap
        self.assertTrue(
            r.match_kind in {"ambiguous", "actor_malware_collision", "family_variant"}
            or "actor_malware_name_overlap" in r.collision_flags
            or "multi_actor" in r.collision_flags
        )
        kinds = {c.ref_kind for c in r.candidates}
        self.assertIn("canonical_actor", kinds)
        self.assertIn("canonical_malware", kinds)

    def test_conti_derived_black_basta_not_auto_merged(self) -> None:
        r = self.by_name["Black Basta"]
        self.assertEqual(r.review_status, "needs_review")
        self.assertFalse(r.auto_merge)
        # override forces review even though exact actor exists
        self.assertTrue(r.override_key)

    def test_royal_and_karakurt_exact(self) -> None:
        for label, slug in (("Royal", "royal"), ("Karakurt", "karakurt")):
            r = self.by_name[label]
            self.assertEqual(r.review_status, "accepted", label)
            self.assertEqual(r.candidates[0].slug, slug, label)
            self.assertFalse(r.auto_merge, label)

    def test_alphv_override_or_alias_to_blackcat(self) -> None:
        r = self.by_name["ALPHV"]
        self.assertEqual(r.review_status, "accepted")
        self.assertEqual(r.confidence, "high")
        self.assertFalse(r.auto_merge)
        self.assertTrue(any(c.slug == "blackcat" for c in r.candidates))

    def test_blackcat_exact(self) -> None:
        r = self.by_name["BlackCat"]
        self.assertEqual(r.review_status, "accepted")
        self.assertEqual(r.candidates[0].slug, "blackcat")

    def test_malware_only_not_actor_merge(self) -> None:
        r = self.by_name["Conti Strain X"]
        self.assertEqual(r.match_kind, "malware_only")
        self.assertEqual(r.review_status, "needs_review")
        self.assertFalse(r.auto_merge)
        self.assertTrue(all(c.ref_kind == "canonical_malware" for c in r.candidates))

    def test_hive_actor_malware_overlap(self) -> None:
        r = self.by_name["Hive"]
        self.assertEqual(r.review_status, "needs_review")
        self.assertEqual(r.match_kind, "actor_malware_collision")
        self.assertFalse(r.auto_merge)
        self.assertIn("actor_malware_name_overlap", r.collision_flags)

    def test_new_candidate(self) -> None:
        r = self.by_name["CompletelyUnknownRaaS"]
        self.assertEqual(r.match_kind, "new_candidate")
        self.assertEqual(r.review_status, "needs_review")
        self.assertEqual(r.confidence, "low")
        self.assertFalse(r.auto_merge)
        self.assertFalse(r.auto_attach_provenance)

    def test_noise_and_event_phrase_rejected(self) -> None:
        for label in ("collaboration", "Decryptor released"):
            r = self.by_name[label]
            self.assertEqual(r.review_status, "rejected", label)
            self.assertFalse(r.auto_merge, label)

    def test_deprecated_abcd(self) -> None:
        r = self.by_name["ABCD"]
        self.assertEqual(r.match_kind, "deprecated")
        self.assertEqual(r.review_status, "rejected")
        self.assertFalse(r.auto_merge)

    def test_nitro_spider_not_merged_into_apt_nitro(self) -> None:
        r = self.by_name["Nitro Spider"]
        self.assertEqual(r.review_status, "needs_review")
        self.assertFalse(r.auto_merge)
        # must not auto-accept as Nitro APT
        if r.candidates:
            slugs = {c.slug for c in r.candidates}
            self.assertNotEqual(slugs, {"nitro"})
        self.assertFalse(r.auto_attach_provenance)

    def test_partial_lock_never_auto_merges(self) -> None:
        r = self.by_name["Lock"]
        self.assertNotEqual(r.review_status, "accepted")
        self.assertFalse(r.auto_merge)
        self.assertIn(r.confidence, {"low", "medium"})

    def test_partition_and_safety_net(self) -> None:
        labels = load_yaml(self.fixtures / "ocd_labels.yml")["labels"]
        records = self.reconciler.reconcile_all(labels)
        # inject a malicious low-conf accepted merge attempt
        poison = self.reconciler.reconcile_label("CompletelyUnknownRaaS")
        poison.review_status = "accepted"
        poison.confidence = "low"
        poison.auto_merge = True
        records.append(poison)
        buckets = self.reconciler.partition(records)
        self.assertNotIn(poison, buckets["accepted"])
        self.assertIn(poison, buckets["needs_review"])
        self.assertFalse(poison.auto_merge)
        for r in buckets["accepted"]:
            self.assertEqual(r.confidence, "high")
            self.assertFalse(r.auto_merge or r.confidence != "high")

    def test_write_outputs(self) -> None:
        import tempfile

        labels = load_yaml(self.fixtures / "ocd_labels.yml")["labels"]
        records = self.reconciler.reconcile_all(labels)
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            report = self.reconciler.write_outputs(records, out)
            self.assertTrue((out / "mappings_accepted.yml").is_file())
            self.assertTrue((out / "mappings_rejected.yml").is_file())
            self.assertTrue((out / "mappings_needs_review.yml").is_file())
            self.assertTrue((out / "reconciliation_report.json").is_file())
            self.assertEqual(report["low_confidence_auto_merge_violations"], 0)
            self.assertGreater(report["totals"]["needs_review"], 0)
            self.assertGreater(report["totals"]["accepted"], 0)
            self.assertGreater(report["totals"]["rejected"], 0)

    def test_low_confidence_override_cannot_accept_merge(self) -> None:
        r = OcdEntityReconciler(
            actors=self.reconciler.actors,
            malware=self.reconciler.malware,
            overrides={
                "accepted": {
                    "FuzzyThing": {
                        "target_slug": "lockbit",
                        "confidence": "low",
                        "allow_merge": True,
                        "reason": "bad idea",
                    }
                }
            },
        ).reconcile_label("FuzzyThing")
        self.assertEqual(r.review_status, "needs_review")
        self.assertFalse(r.auto_merge)
        self.assertFalse(r.auto_attach_provenance)


if __name__ == "__main__":
    unittest.main(verbosity=2)
