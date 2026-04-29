# Importer supersession and provenance backlog

This document tracks engineering follow-ups called out in [Data flow assessment](data-flows.md). Imports already populate much of `_data/actors/*.yml`; the gaps are **consistent merge rules** and **field-level provenance**, not always missing importer scripts.

## Backlog

| ID | Item | Source discussion |
|----|------|-------------------|
| SB-1 | Centralize manual-takeover behavior in shared importer utilities (MISP Galaxy, MITRE, Malpedia, APTnotes, APT Groups & Operations) | [data-flows.md § Supersession gaps](data-flows.md#supersession-gaps-to-close) |
| SB-2 | Add field-level provenance for arrays: `malware`, `operations`, `ttps`, IOC-related fields | Same |
| SB-3 | Validate YAML with `source_name: "Analyst Notes"` is superseded when automated provenance exists | Same |
| SB-4 | Retire or formalize one-off import scripts that lack snapshot/plan/apply semantics | Same |

## Related docs

- [Importers](importers.md)
- [Schema](schema.md)
- [Contributing](../CONTRIBUTING.md)

Progress on these items should update this table and [data-flows.md](data-flows.md) assessment language.
