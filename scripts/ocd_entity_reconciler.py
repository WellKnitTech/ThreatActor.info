#!/usr/bin/env python3
"""Alias-aware reconciliation of OCD ransomware-map labels vs ThreatActor.info entities.

Design alignment (t_b23bf880 / AliasResolver):
- Exact name/alias matches may attach provenance; they never rename or merge slugs.
- Non-exact matches require confidence + review_status.
- Low-confidence labels never auto-merge into an existing actor.
- Family / operation / affiliate_group / malware_strain remain distinct.
- Outputs partition into accepted / rejected / needs_review.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Iterable

import yaml

CONFIDENCE_RANK = {"low": 0, "medium": 1, "high": 2}

# Version / builder suffixes often painted on the OCD plate as family lineage nodes.
VERSION_TAIL_RE = re.compile(
    r"""^(?P<head>.+?)[\s\-_]*
        (?P<tail>
            (?:v?\d+(?:\.\d+){0,3}) |
            (?:green|black|white|esxi|linux|builder|affiliates?)
        )
        $""",
    re.IGNORECASE | re.VERBOSE,
)

# Soft / fuzzy tails that must never auto-accept.
LOW_SIGNAL_LABEL_RE = re.compile(
    r"^(code|attack|and|as|before|between|collaboration|copy|details|"
    r"enforcement|from|having|affiliation|alleged|arrests|decryptor|"
    r"disruptions|doxxed|debated)$",
    re.IGNORECASE,
)


def load_yaml(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def dump_yaml(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        yaml.safe_dump(data, fh, sort_keys=False, allow_unicode=True)


def canonical_key(value: Any) -> str | None:
    """Mirror scripts/lib/alias_resolver.rb canonical_key (leet-normalized)."""
    if value is None:
        return None
    s = str(value).strip().lower()
    if not s:
        return None
    s = (
        s.replace("0", "o")
        .replace("1", "l")
        .replace("3", "e")
        .replace("4", "a")
        .replace("5", "s")
    )
    s = re.sub(r"[@\-_\s]+", "", s)
    s = re.sub(r"[^a-z0-9]+", "", s)
    return s or None


def strict_key(value: Any) -> str | None:
    """Non-leet normalization for version/base comparisons."""
    if value is None:
        return None
    s = str(value).strip().lower()
    if not s:
        return None
    s = re.sub(r"[^a-z0-9]+", "", s)
    return s or None


def slugify(value: str) -> str:
    s = str(value).strip().lower()
    s = re.sub(r"[^a-z0-9]+", "-", s)
    return s.strip("-")


def external_mention_id(map_version: int | str, label: str) -> str:
    return f"ocd:mention:v{map_version}:{slugify(label)}"


def split_versioned_label(label: str) -> tuple[str | None, str | None]:
    m = VERSION_TAIL_RE.match(label.strip())
    if not m:
        return None, None
    head = m.group("head").strip(" -_")
    tail = m.group("tail")
    if not head or len(strict_key(head) or "") < 3:
        return None, None
    return head, tail


@dataclass
class EntityRef:
    ref_kind: str  # canonical_actor | canonical_malware | candidate_entity | external_name
    canonical_id: str | None
    slug: str | None
    display_name: str
    hit_via: str
    entity_type: str | None = None

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        return {k: v for k, v in d.items() if v is not None}


@dataclass
class MappingRecord:
    label_raw: str
    label_normalized: str
    external_id: str
    match_kind: str
    confidence: str
    review_status: str
    auto_merge: bool
    auto_attach_provenance: bool
    entity_type_hint: str | None = None
    candidates: list[EntityRef] = field(default_factory=list)
    collision_flags: list[str] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)
    source_snapshot_id: str | None = None
    override_key: str | None = None
    first_seen_hint: str | None = None
    changelog_section: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "label_raw": self.label_raw,
            "label_normalized": self.label_normalized,
            "external_id": self.external_id,
            "match_kind": self.match_kind,
            "confidence": self.confidence,
            "review_status": self.review_status,
            "auto_merge": self.auto_merge,
            "auto_attach_provenance": self.auto_attach_provenance,
            "entity_type_hint": self.entity_type_hint,
            "candidates": [c.to_dict() for c in self.candidates],
            "collision_flags": list(self.collision_flags),
            "reasons": list(self.reasons),
            "source_snapshot_id": self.source_snapshot_id,
            "override_key": self.override_key,
            "first_seen_hint": self.first_seen_hint,
            "changelog_section": self.changelog_section,
        }


class OcdEntityReconciler:
    def __init__(
        self,
        actors: list[dict[str, Any]],
        malware: list[dict[str, Any]] | None = None,
        overrides: dict[str, Any] | None = None,
        map_version: int | str = 29,
        source_snapshot_id: str | None = None,
    ) -> None:
        self.actors = [a for a in actors if isinstance(a, dict) and a.get("name")]
        self.malware = [m for m in (malware or []) if isinstance(m, dict) and m.get("name")]
        self.overrides = overrides or {}
        self.map_version = map_version
        self.source_snapshot_id = source_snapshot_id or f"ocd:snapshot:v{map_version}:reconcile"
        self._actor_index: dict[str, list[int]] = {}
        self._malware_index: dict[str, list[int]] = {}
        self._build_indexes()

    # --- loading helpers -------------------------------------------------

    @classmethod
    def from_paths(
        cls,
        actors_dir: Path,
        malware_dir: Path | None = None,
        overrides_path: Path | None = None,
        map_version: int | str = 29,
        source_snapshot_id: str | None = None,
    ) -> "OcdEntityReconciler":
        actors = cls._load_actor_dir(actors_dir)
        malware = cls._load_malware_dir(malware_dir) if malware_dir else []
        overrides = load_yaml(overrides_path) if overrides_path and overrides_path.is_file() else {}
        return cls(
            actors=actors,
            malware=malware,
            overrides=overrides or {},
            map_version=map_version,
            source_snapshot_id=source_snapshot_id,
        )

    @staticmethod
    def _load_actor_dir(path: Path) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        for p in sorted(path.glob("*.yml")) + sorted(path.glob("*.yaml")):
            data = load_yaml(p)
            if not isinstance(data, dict):
                continue
            data = dict(data)
            data.setdefault("_path", str(p))
            if not data.get("url"):
                data["url"] = f"/{p.stem}"
            rows.append(data)
        return rows

    @staticmethod
    def _load_malware_dir(path: Path) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        if not path or not path.exists():
            return rows
        for p in sorted(path.glob("*.yml")) + sorted(path.glob("*.yaml")):
            data = load_yaml(p)
            if isinstance(data, dict) and data.get("name"):
                data = dict(data)
                data.setdefault("slug", p.stem)
                rows.append(data)
        for p in sorted(path.glob("*.data.json")):
            try:
                data = json.loads(p.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                continue
            if isinstance(data, dict) and data.get("name"):
                data = dict(data)
                data.setdefault("slug", data.get("slug") or p.name.replace(".data.json", ""))
                rows.append(data)
        return rows

    def _build_indexes(self) -> None:
        for i, actor in enumerate(self.actors):
            keys = set()
            for value in [actor.get("name"), actor.get("url"), *list(actor.get("aliases") or [])]:
                ck = canonical_key(value)
                sk = strict_key(value)
                if ck:
                    keys.add(ck)
                if sk:
                    keys.add(sk)
            slug = str(actor.get("url") or "").strip("/")
            if slug:
                keys.add(slug)
                sk = strict_key(slug)
                if sk:
                    keys.add(sk)
            for k in keys:
                self._actor_index.setdefault(k, []).append(i)

        for i, mal in enumerate(self.malware):
            keys = set()
            for value in [mal.get("name"), mal.get("slug"), *list(mal.get("aliases") or [])]:
                ck = canonical_key(value)
                sk = strict_key(value)
                if ck:
                    keys.add(ck)
                if sk:
                    keys.add(sk)
            for k in keys:
                self._malware_index.setdefault(k, []).append(i)

    # --- override lookup -------------------------------------------------

    def _override_bucket(self) -> dict[str, dict[str, Any]]:
        """Flatten accepted/rejected/needs_review/deprecated override maps by canonical key."""
        out: dict[str, dict[str, Any]] = {}
        for status in ("accepted", "rejected", "needs_review", "deprecated"):
            block = self.overrides.get(status) or {}
            if not isinstance(block, dict):
                continue
            for raw_key, meta in block.items():
                k = canonical_key(raw_key) or strict_key(raw_key)
                if not k:
                    continue
                entry = dict(meta) if isinstance(meta, dict) else {"target": meta}
                entry["_status"] = status
                entry["_raw_key"] = raw_key
                out[k] = entry
        # also support match_overrides like ransomlook (forced accepted target slug)
        for raw_key, target in (self.overrides.get("match_overrides") or {}).items():
            k = canonical_key(raw_key) or strict_key(raw_key)
            if not k or k in out:
                continue
            out[k] = {
                "_status": "accepted",
                "target_slug": str(target).strip("/"),
                "confidence": "high",
                "reason": "match_override",
                "_raw_key": raw_key,
            }
        return out

    def _actor_by_slug(self, slug: str) -> dict[str, Any] | None:
        slug = slug.strip("/")
        for actor in self.actors:
            if str(actor.get("url") or "").strip("/") == slug:
                return actor
            if strict_key(actor.get("name")) == strict_key(slug):
                return actor
        return None

    def _malware_by_slug(self, slug: str) -> dict[str, Any] | None:
        slug = slug.strip("/")
        for mal in self.malware:
            if str(mal.get("slug") or "") == slug:
                return mal
            if strict_key(mal.get("name")) == strict_key(slug):
                return mal
        return None

    # --- core match ------------------------------------------------------

    def _lookup_actors(self, *names: str) -> list[int]:
        hits: list[int] = []
        for name in names:
            for key_fn in (canonical_key, strict_key):
                k = key_fn(name)
                if k and k in self._actor_index:
                    hits.extend(self._actor_index[k])
        # unique preserve order
        seen = set()
        out = []
        for i in hits:
            if i not in seen:
                seen.add(i)
                out.append(i)
        return out

    def _lookup_malware(self, *names: str) -> list[int]:
        hits: list[int] = []
        for name in names:
            for key_fn in (canonical_key, strict_key):
                k = key_fn(name)
                if k and k in self._malware_index:
                    hits.extend(self._malware_index[k])
        seen = set()
        out = []
        for i in hits:
            if i not in seen:
                seen.add(i)
                out.append(i)
        return out

    def _actor_ref(self, actor: dict[str, Any], hit_via: str, entity_type: str | None = None) -> EntityRef:
        slug = str(actor.get("url") or "").strip("/")
        return EntityRef(
            ref_kind="canonical_actor",
            canonical_id=f"actor:{slug}" if slug else None,
            slug=slug or None,
            display_name=str(actor.get("name")),
            hit_via=hit_via,
            entity_type=entity_type or "operation",
        )

    def _malware_ref(self, mal: dict[str, Any], hit_via: str) -> EntityRef:
        slug = str(mal.get("slug") or slugify(mal.get("name") or "unknown"))
        return EntityRef(
            ref_kind="canonical_malware",
            canonical_id=f"malware:{slug}",
            slug=slug,
            display_name=str(mal.get("name")),
            hit_via=hit_via,
            entity_type="malware_strain",
        )

    def reconcile_label(self, label: dict[str, Any] | str) -> MappingRecord:
        if isinstance(label, str):
            label = {"name": label}
        raw = str(label.get("name") or label.get("label") or "").strip()
        if not raw:
            raise ValueError("label missing name")

        norm = canonical_key(raw) or strict_key(raw) or slugify(raw)
        external_id = label.get("external_id") or external_mention_id(self.map_version, raw)
        aliases = [str(a) for a in (label.get("aliases") or [])]
        entity_type_hint = label.get("entity_type") or label.get("entity_type_hint")
        first_seen_hint = label.get("first_seen_hint")
        changelog_section = label.get("changelog_section") or label.get("section")

        base = MappingRecord(
            label_raw=raw,
            label_normalized=norm,
            external_id=external_id,
            match_kind="none",
            confidence="low",
            review_status="needs_review",
            auto_merge=False,
            auto_attach_provenance=False,
            entity_type_hint=entity_type_hint,
            source_snapshot_id=self.source_snapshot_id,
            first_seen_hint=first_seen_hint,
            changelog_section=changelog_section,
        )

        if LOW_SIGNAL_LABEL_RE.match(raw) or len(norm) < 3:
            base.match_kind = "noise"
            base.confidence = "low"
            base.review_status = "rejected"
            base.reasons.append("low-signal or noise label; not an entity")
            base.auto_merge = False
            return base

        # 1) Explicit overrides always win and set review_status.
        ovr_map = self._override_bucket()
        ovr = ovr_map.get(norm) or ovr_map.get(strict_key(raw) or "")
        if ovr:
            return self._apply_override(base, ovr)

        # 2) Collect actor / malware hits for label + aliases.
        name_list = [raw, *aliases]
        actor_idxs = self._lookup_actors(*name_list)
        mal_idxs = self._lookup_malware(*name_list)

        # 3) Version / family head expansion (LockBit 3.0 -> LockBit).
        head, tail = split_versioned_label(raw)
        family_actor_idxs: list[int] = []
        if head:
            family_actor_idxs = self._lookup_actors(head)
            # also try malware on full label and head
            if not mal_idxs:
                mal_idxs = self._lookup_malware(raw, head)

        # Exactness: does any actor have exact name or alias string-equal ignoring case?
        exact_actor_idxs = []
        normalized_only = []
        for i in actor_idxs:
            actor = self.actors[i]
            names = [str(actor.get("name") or "")] + [str(a) for a in (actor.get("aliases") or [])]
            if any(n.strip().lower() == raw.lower() for n in names):
                exact_actor_idxs.append(i)
            elif any(canonical_key(n) == norm or strict_key(n) == strict_key(raw) for n in names):
                normalized_only.append(i)
            else:
                # matched via slug / leet path
                normalized_only.append(i)

        collision_flags: list[str] = []
        candidates: list[EntityRef] = []
        reasons: list[str] = []

        if exact_actor_idxs and len(set(exact_actor_idxs)) > 1:
            collision_flags.append("multi_actor_exact")
        if actor_idxs and len(actor_idxs) > 1:
            collision_flags.append("multi_actor")
        if mal_idxs and actor_idxs:
            collision_flags.append("actor_malware_name_overlap")
        if family_actor_idxs and tail:
            collision_flags.append("family_variant")
        if entity_type_hint == "malware_strain" and actor_idxs:
            collision_flags.append("typed_malware_vs_actor")
        if entity_type_hint in {"ransomware_family", "operation"} and mal_idxs and not actor_idxs:
            collision_flags.append("typed_family_vs_malware_only")

        # Build candidate refs
        hit_via_exact = "exact_name_or_alias"
        for i in exact_actor_idxs:
            candidates.append(self._actor_ref(self.actors[i], hit_via_exact, entity_type_hint))
        for i in actor_idxs:
            if i in exact_actor_idxs:
                continue
            candidates.append(self._actor_ref(self.actors[i], "normalized_alias", entity_type_hint))
        for i in family_actor_idxs:
            if i in actor_idxs or i in exact_actor_idxs:
                # still annotate family link if versioned
                if tail:
                    candidates.append(
                        self._actor_ref(self.actors[i], f"family_base:{tail}", "ransomware_family")
                    )
                continue
            if tail:
                candidates.append(
                    self._actor_ref(self.actors[i], f"family_base:{tail}", "ransomware_family")
                )
        for i in mal_idxs:
            candidates.append(self._malware_ref(self.malware[i], "malware_name"))

        # Dedup candidates by canonical_id+hit_via
        dedup = []
        seen_c = set()
        for c in candidates:
            sig = (c.canonical_id, c.hit_via)
            if sig in seen_c:
                continue
            seen_c.add(sig)
            dedup.append(c)
        candidates = dedup

        base.candidates = candidates
        base.collision_flags = collision_flags

        # Classification
        unique_exact_actors = sorted(set(exact_actor_idxs))
        unique_actors = sorted(set(actor_idxs))
        unique_family = sorted(set(family_actor_idxs))
        unique_mal = sorted(set(mal_idxs))

        # Ambiguous multi-actor on the label itself
        if len(unique_exact_actors) > 1 or (not unique_exact_actors and len(unique_actors) > 1):
            base.match_kind = "ambiguous"
            base.confidence = "low"
            base.review_status = "needs_review"
            base.auto_merge = False
            base.auto_attach_provenance = False
            reasons.append("multiple actor candidates; no automatic merge")
            base.reasons = reasons
            return base

        # Versioned family node (LockBit 3.0): never auto-merge into parent operator
        if tail and (unique_family or unique_mal or unique_actors):
            base.match_kind = "family_variant"
            base.confidence = "medium" if (unique_family or unique_actors) else "low"
            base.review_status = "needs_review"
            base.auto_merge = False
            base.auto_attach_provenance = False
            base.entity_type_hint = base.entity_type_hint or "ransomware_family"
            reasons.append(
                f"version/family suffix '{tail}' — keep distinct from parent operator; analyst review required"
            )
            if unique_mal:
                reasons.append("overlapping malware strain record present")
            base.reasons = reasons
            return base

        # An explicit malware type cannot be accepted as actor provenance when
        # the only exact match is an actor and no malware catalog entry exists.
        if entity_type_hint == "malware_strain" and len(unique_exact_actors) == 1 and not unique_mal:
            base.match_kind = "typed_actor_collision"
            base.confidence = "medium"
            base.review_status = "needs_review"
            base.auto_merge = False
            base.auto_attach_provenance = False
            reasons.append("explicit malware_strain type conflicts with actor-only exact match; analyst review required")
            base.reasons = reasons
            return base

        # Exact single actor, no malware collision
        if len(unique_exact_actors) == 1 and not unique_mal:
            base.match_kind = "exact_alias" if raw.lower() != str(self.actors[unique_exact_actors[0]].get("name")).lower() else "exact_name"
            # If hit via alias that is a different popular brand (Conti alias Ryuk handled by multi), single is ok
            base.confidence = "high"
            base.review_status = "accepted"
            base.auto_merge = False  # never identity-merge
            base.auto_attach_provenance = True
            base.entity_type_hint = base.entity_type_hint or "operation"
            reasons.append("exact canonical name/alias match; provenance attach only, no merge/rename")
            base.reasons = reasons
            return base

        # Exact single actor WITH malware overlap → type collision
        if len(unique_exact_actors) == 1 and unique_mal:
            base.match_kind = "actor_malware_collision"
            base.confidence = "medium"
            base.review_status = "needs_review"
            base.auto_merge = False
            base.auto_attach_provenance = False
            reasons.append("label matches both actor and malware entities; keep types separate")
            base.reasons = reasons
            return base

        # Normalized single actor (leet/punct), no malware
        if not unique_exact_actors and len(unique_actors) == 1 and not unique_mal:
            base.match_kind = "normalized"
            base.confidence = "medium"
            base.review_status = "needs_review"
            base.auto_merge = False
            base.auto_attach_provenance = False
            reasons.append("normalized-only match; require analyst confirmation before provenance attach")
            base.reasons = reasons
            return base

        # Malware only
        if unique_mal and not unique_actors and not unique_family:
            base.match_kind = "malware_only"
            base.confidence = "medium" if len(unique_mal) == 1 else "low"
            base.review_status = "needs_review"
            base.auto_merge = False
            base.auto_attach_provenance = False
            base.entity_type_hint = base.entity_type_hint or "malware_strain"
            reasons.append("matches malware catalog only; do not create/merge actor from malware name")
            if len(unique_mal) > 1:
                reasons.append("multiple malware candidates")
            base.reasons = reasons
            return base

        # Normalized multi or family-only without tail handled above
        if unique_family and not unique_actors:
            base.match_kind = "family_base_only"
            base.confidence = "low"
            base.review_status = "needs_review"
            base.auto_merge = False
            base.auto_attach_provenance = False
            reasons.append("only family-base fuzzy association")
            base.reasons = reasons
            return base

        # No match → new candidate watchlist, never auto actor page
        base.match_kind = "new_candidate"
        base.confidence = "low"
        base.review_status = "needs_review"
        base.auto_merge = False
        base.auto_attach_provenance = False
        base.candidates = [
            EntityRef(
                ref_kind="candidate_entity",
                canonical_id=None,
                slug=None,
                display_name=raw,
                hit_via="unmatched",
                entity_type=entity_type_hint or "unknown",
            )
        ]
        reasons.append("no actor/malware match; retain as source-local candidate (no auto actor page)")
        base.reasons = reasons
        return base

    def _apply_override(self, base: MappingRecord, ovr: dict[str, Any]) -> MappingRecord:
        status = ovr.get("_status") or "needs_review"
        base.override_key = str(ovr.get("_raw_key") or base.label_raw)
        base.reasons.append(str(ovr.get("reason") or f"mapping_overrides:{status}"))
        conf = str(ovr.get("confidence") or ("high" if status == "accepted" else "medium")).lower()
        if conf not in CONFIDENCE_RANK:
            conf = "medium"
        base.confidence = conf
        base.entity_type_hint = ovr.get("entity_type") or base.entity_type_hint

        target_slug = ovr.get("target_slug") or ovr.get("target") or ovr.get("canonical_slug")
        target_malware = ovr.get("target_malware_slug")
        allow_merge = bool(ovr.get("allow_merge", False))

        if target_slug:
            actor = self._actor_by_slug(str(target_slug))
            if actor:
                base.candidates.append(self._actor_ref(actor, "override", base.entity_type_hint))
            else:
                base.candidates.append(
                    EntityRef(
                        ref_kind="external_name",
                        canonical_id=f"actor:{str(target_slug).strip('/')}",
                        slug=str(target_slug).strip("/"),
                        display_name=str(target_slug),
                        hit_via="override_missing_actor",
                        entity_type=base.entity_type_hint,
                    )
                )
                base.reasons.append("override target actor slug not present in loaded corpus")
                if status == "accepted":
                    status = "needs_review"
                    conf = "low"
                    base.confidence = conf

        if target_malware:
            mal = self._malware_by_slug(str(target_malware))
            if mal:
                base.candidates.append(self._malware_ref(mal, "override"))
            else:
                base.candidates.append(
                    EntityRef(
                        ref_kind="canonical_malware",
                        canonical_id=f"malware:{target_malware}",
                        slug=str(target_malware),
                        display_name=str(target_malware),
                        hit_via="override_missing_malware",
                        entity_type="malware_strain",
                    )
                )

        if status == "deprecated":
            base.match_kind = "deprecated"
            base.review_status = "rejected"
            base.auto_merge = False
            base.auto_attach_provenance = False
            base.confidence = conf if conf != "high" else "medium"
            base.reasons.append("deprecated upstream/editorial name; do not revive as canonical")
            return base

        if status == "rejected":
            base.match_kind = "override_rejected"
            base.review_status = "rejected"
            base.auto_merge = False
            base.auto_attach_provenance = False
            return base

        if status == "needs_review":
            base.match_kind = "override_review"
            base.review_status = "needs_review"
            base.auto_merge = False
            base.auto_attach_provenance = False
            return base

        # accepted override
        base.match_kind = "override_accepted"
        base.review_status = "accepted"
        # Hard rule: never auto-merge low confidence
        if CONFIDENCE_RANK[base.confidence] < CONFIDENCE_RANK["high"]:
            base.auto_merge = False
            base.auto_attach_provenance = False
            base.review_status = "needs_review"
            base.reasons.append("low/medium confidence override cannot auto-merge or auto-accept")
            return base
        base.auto_merge = bool(allow_merge)  # default false even on accepted
        base.auto_attach_provenance = not base.auto_merge
        if allow_merge:
            base.reasons.append("explicit allow_merge=true on high-confidence accepted override")
        else:
            base.reasons.append("accepted override: provenance attach only unless allow_merge")
        return base

    def reconcile_all(self, labels: Iterable[dict[str, Any] | str]) -> list[MappingRecord]:
        out: list[MappingRecord] = []
        seen_norm: set[str] = set()
        for label in labels:
            rec = self.reconcile_label(label)
            # de-dupe identical normalized labels within one run (keep first)
            if rec.label_normalized in seen_norm:
                rec.reasons.append("duplicate label in input batch (retained)")
            seen_norm.add(rec.label_normalized)
            out.append(rec)
        return out

    def partition(self, records: list[MappingRecord]) -> dict[str, list[MappingRecord]]:
        buckets = {"accepted": [], "rejected": [], "needs_review": []}
        for r in records:
            # Safety net: never let low-confidence land in accepted with auto_merge
            if r.review_status == "accepted" and CONFIDENCE_RANK.get(r.confidence, 0) < CONFIDENCE_RANK["high"]:
                r.review_status = "needs_review"
                r.auto_merge = False
                r.auto_attach_provenance = False
                r.reasons.append("safety: demoted accepted→needs_review due to non-high confidence")
            if r.auto_merge and CONFIDENCE_RANK.get(r.confidence, 0) < CONFIDENCE_RANK["high"]:
                r.auto_merge = False
                r.reasons.append("safety: cleared auto_merge on non-high confidence")
            if r.review_status == "accepted":
                buckets["accepted"].append(r)
            elif r.review_status == "rejected":
                buckets["rejected"].append(r)
            else:
                buckets["needs_review"].append(r)
        return buckets

    def write_outputs(self, records: list[MappingRecord], out_dir: Path) -> dict[str, Any]:
        out_dir.mkdir(parents=True, exist_ok=True)
        buckets = self.partition(records)
        for name, rows in buckets.items():
            dump_yaml(
                out_dir / f"mappings_{name}.yml",
                {
                    "source_key": "ocd-ransomware-map",
                    "map_version": self.map_version,
                    "source_snapshot_id": self.source_snapshot_id,
                    "count": len(rows),
                    "mappings": [r.to_dict() for r in rows],
                },
            )
        report = {
            "source_key": "ocd-ransomware-map",
            "map_version": self.map_version,
            "source_snapshot_id": self.source_snapshot_id,
            "totals": {k: len(v) for k, v in buckets.items()},
            "auto_merge_true_count": sum(1 for r in records if r.auto_merge),
            "auto_attach_provenance_count": sum(1 for r in records if r.auto_attach_provenance),
            "low_confidence_auto_merge_violations": sum(
                1 for r in records if r.auto_merge and CONFIDENCE_RANK.get(r.confidence, 0) < CONFIDENCE_RANK["high"]
            ),
            "match_kind_histogram": _histogram(r.match_kind for r in records),
            "records": [r.to_dict() for r in records],
        }
        (out_dir / "reconciliation_report.json").write_text(
            json.dumps(report, indent=2, sort_keys=False) + "\n", encoding="utf-8"
        )
        return report


def _histogram(values: Iterable[str]) -> dict[str, int]:
    h: dict[str, int] = {}
    for v in values:
        h[v] = h.get(v, 0) + 1
    return dict(sorted(h.items(), key=lambda kv: (-kv[1], kv[0])))


def labels_from_changelog_parsed(parsed: dict[str, Any], version_key: str = "V29") -> list[dict[str, Any]]:
    """Build label rows from research parsed.json changelog structure."""
    changelog = (parsed or {}).get("changelog") or {}
    block = changelog.get(version_key) or {}
    labels: list[dict[str, Any]] = []
    for item in block.get("adds") or []:
        if isinstance(item, dict) and item.get("name"):
            labels.append(
                {
                    "name": item["name"],
                    "first_seen_hint": item.get("first_seen_hint"),
                    "changelog_section": "add",
                    "entity_type": "unknown",
                }
            )
        elif isinstance(item, str):
            labels.append({"name": item, "changelog_section": "add", "entity_type": "unknown"})
    for name in block.get("edits") or []:
        labels.append({"name": str(name), "changelog_section": "edit", "entity_type": "unknown"})
    return labels


def stable_json_sha(data: Any) -> str:
    blob = json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()
