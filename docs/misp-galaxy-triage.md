This note tracks reviewed create/import decisions for focused MISP Galaxy snapshots.

Current working set:

- Snapshot: `tmp/misp-galaxy-hotspots`
- Plan report: `tmp/import-reports/misp-galaxy-360net-microsoft-plan.json`
- Focused clusters: `360net.json`, `microsoft-activity-group.json`

## Imported in controlled batches

### 360net batch

- `毒针 - APT-C-31`
- `军刀狮 - APT-C-38`
- `拍拍熊 - APT-C-37`
- `人面狮 - APT-C-15`
- `美人鱼 - APT-C-07`
- `毒云藤 - APT-C-01`
- `潜行者 - APT-C-30`
- `腾云蛇 - APT-C-61`
- `卢甘斯克组织 - APT-C-46`
- `蓝色魔眼 - APT-C-41`
- `北非狐 - APT-C-44`

### Microsoft activity-group batch

- `Crescent Typhoon`
- `Houndstooth Typhoon`
- `Night Tsunami`
- `Tumbleweed Typhoon`
- `Volga Flood`
- `Wisteria Tsunami`

## Remaining create triage

### Conditional next wave

- `Berry Sandstorm` - plausible Iran-linked create, but still mostly anchored to `Storm-0852`
- `Clay Typhoon` - net-new China bucket, but `Storm-2416` alone is still thin
- `Jasper Sleet` - useful DPRK coverage, though identity is still mostly Microsoft-internal beyond `Storm-0287`
- `Ruza Flood` - viable Russia influence-op candidate, but lacks a strong public alias
- `Sefid Flood` - same issue as `Ruza Flood`; plausible but still mostly a vendor label
- `Storm-1982` - `SneakyCheff` / `UNK_SweetSpecter` is promising, but alias consistency is weak
- `Wheat Tempest` - `Gatak` may matter, but actor-vs-malware ambiguity remains
- `Yulong Flood` - fits China influence coverage, but `Storm-1852` is sparse on its own

### Defer

- `Luna Tempest` - too generic: no country, no synonym, no clear durable identity
- `Storm-2035` - pure numeric Microsoft label with no external anchor
- `Storm-2470` - same issue as `Storm-2035`; too little public identity
- `Storm-2755` - financially motivated numeric bucket with no stable public naming

## Remaining review-only collisions

- `摩诃草 - APT-C-09`
- `双尾蝎 - APT-C-23`
- `索伦之眼 - APT-C-16`
- `Citrine Sleet`
- `Crimson Sandstorm`
- `Cuboid Sandstorm`
- `Hazel Sandstorm`
- `Jade Sleet`
- `Pinstripe Lightning`
- `Sapphire Sleet`
- `Smoke Sandstorm`
- `Spandex Tempest`
- `Storm-0230`
- `Twill Typhoon`

These remain review-only because the current corpus preserves parallel local records, overlapping umbrella/subcluster relationships, or vendor-family ambiguity that should not be auto-resolved by overrides yet.
