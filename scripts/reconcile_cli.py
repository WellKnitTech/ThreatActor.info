#!/usr/bin/env python3
"""CLI for OCD ransomware-map label reconciliation."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from ocd_entity_reconciler import (
    OcdEntityReconciler,
    labels_from_changelog_parsed,
    load_yaml,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--actors-dir",
        type=Path,
        required=True,
        help="Directory of actor YAML files (_data/actors)",
    )
    parser.add_argument(
        "--malware-dir",
        type=Path,
        default=None,
        help="Optional malware YAML/JSON directory",
    )
    parser.add_argument(
        "--labels",
        type=Path,
        required=True,
        help="YAML file with labels: [...] or changelog-style list",
    )
    parser.add_argument(
        "--overrides",
        type=Path,
        default=None,
        help="mapping_overrides.yml",
    )
    parser.add_argument(
        "--out-dir",
        type=Path,
        required=True,
        help="Output directory for accepted/rejected/needs_review mappings",
    )
    parser.add_argument("--map-version", default="29")
    parser.add_argument("--snapshot-id", default=None)
    parser.add_argument(
        "--from-parsed-changelog",
        action="store_true",
        help="Interpret --labels JSON as research parsed.json and use changelog.V29",
    )
    parser.add_argument(
        "--changelog-version",
        default="V29",
        help="Changelog key when using --from-parsed-changelog",
    )
    args = parser.parse_args(argv)

    reconciler = OcdEntityReconciler.from_paths(
        actors_dir=args.actors_dir,
        malware_dir=args.malware_dir,
        overrides_path=args.overrides,
        map_version=args.map_version,
        source_snapshot_id=args.snapshot_id,
    )

    if args.from_parsed_changelog:
        parsed = json.loads(args.labels.read_text(encoding="utf-8"))
        labels = labels_from_changelog_parsed(parsed, version_key=args.changelog_version)
    else:
        payload = load_yaml(args.labels)
        if isinstance(payload, list):
            labels = payload
        elif isinstance(payload, dict):
            labels = payload.get("labels") or payload.get("mentions") or []
            if payload.get("map_version") and args.map_version == "29":
                reconciler.map_version = payload["map_version"]
            if payload.get("source_snapshot_id") and not args.snapshot_id:
                reconciler.source_snapshot_id = payload["source_snapshot_id"]
        else:
            print("Unsupported labels document", file=sys.stderr)
            return 2

    records = reconciler.reconcile_all(labels)
    report = reconciler.write_outputs(records, args.out_dir)

    print(
        "OCD reconcile:",
        f"accepted={report['totals']['accepted']}",
        f"rejected={report['totals']['rejected']}",
        f"needs_review={report['totals']['needs_review']}",
        f"auto_merge_true={report['auto_merge_true_count']}",
        f"low_conf_merge_violations={report['low_confidence_auto_merge_violations']}",
    )
    print(f"Wrote {args.out_dir}")
    if report["low_confidence_auto_merge_violations"]:
        return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
