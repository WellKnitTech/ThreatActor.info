# ThreatActor.info

A community-driven threat intelligence wiki that collects and organizes information about various threat actors, APT groups, and cybercriminal organizations. This project aims to provide a centralized, searchable database of threat actor information that the cybersecurity community can contribute to and benefit from.

## 🎯 Project Goals

- **Centralized Intelligence**: Collect threat actor information in one accessible location
- **Community-Driven**: Enable cybersecurity professionals to contribute and share knowledge
- **Searchable Database**: Provide advanced search and filtering capabilities
- **Standardized Format**: Maintain consistent data structure and content format
- **Open Source**: Keep the project open and accessible to the community

## 🚀 Features

### Current Features
- **15+ Threat Actors**: Comprehensive database of major APT groups and cybercriminal organizations
- **Advanced Search**: Filter by country, risk level, sector focus, and keywords
- **Static JSON API**: Publish generated threat actor, IOC, and facet endpoints under `api/`
- **Rich Metadata**: Country attribution, risk levels, sector focus, activity timelines
- **Responsive Design**: Mobile-friendly interface with modern UI
- **Fast Performance**: Static site generation for optimal loading speeds

### Threat Actor Information Includes
- **Basic Information**: Names, aliases, descriptions
- **Attribution**: Country of origin, sector focus
- **Activity Timeline**: First seen, last activity dates
- **Risk Assessment**: Risk level classification
- **Tactics & Techniques**: TTPs, MITRE ATT&CK mappings
- **Indicators of Compromise**: IPs, domains, file hashes
- **Malware & Tools**: Associated malware families and tools
- **Notable Campaigns**: Major attacks and operations
- **References**: Links to reports and analysis

## 🛠️ Technology Stack

- **Jekyll 4.0**: Static site generator
- **Liquid**: Templating engine
- **YAML**: Data structure and configuration
- **Markdown**: Content authoring
- **CSS Grid/Flexbox**: Modern responsive design
- **JavaScript**: Enhanced search and filtering
- **GitHub Pages**: Hosting and deployment

## 📁 Project Structure

```
threatactor-info/
├── _config.yml              # Jekyll configuration
├── _data/
│   ├── threat_actors.yml    # Central threat actor database
│   └── generated/           # Generated JSON artifacts for APIs/search
├── _layouts/
│   ├── default.html         # Base layout template
│   └── threat_actor.html    # Threat actor page template
├── _includes/
│   └── search.html          # Search functionality
├── _threat_actors/          # Individual threat actor pages
│   ├── apt28.md
│   ├── apt29.md
│   └── ...
├── api/
│   ├── threat-actors.json   # Static threat actor API endpoint
│   ├── iocs.json            # Static IOC API endpoint
│   └── facets.json          # Static facet API endpoint
├── scripts/
│   ├── generate-indexes.rb  # Generates JSON indexes from YAML + Markdown
│   └── validate-content.rb  # Content and generated artifact validator
├── assets/
│   └── css/
│       └── style.scss       # Custom styles
├── index.html               # Home page
├── threat-actors.html       # Threat actors listing
└── search.json              # Search index
```

## 🚀 Getting Started

### Prerequisites
- Ruby 3.2.5
- Bundler
- Git

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/your-username/threatactor-info.git
   cd threatactor-info
   ```

2. **Install dependencies**
   ```bash
   gem install bundler -v 2.5.10
   bundle install
   ```

3. **Generate indexes**
   ```bash
   ruby scripts/generate-indexes.rb
   ```

4. **Optional: prepare imported actor snapshots**
   ```bash
   ruby scripts/import-ransomlook.rb fetch --output data/imports/ransomlook/$(date +%F) --limit 10
   ruby scripts/import-ransomlook.rb plan --snapshot data/imports/ransomlook/$(date +%F)
   ```

5. **Run locally**
   ```bash
   bundle exec jekyll serve
   ```

6. **Access the site**
    Open [http://localhost:4000](http://localhost:4000) in your browser

### Development

1. **Make changes** to threat actor data, content, or styling
2. **Regenerate JSON artifacts** using `ruby scripts/generate-indexes.rb`
3. **Run validation** using `ruby scripts/validate-content.rb`
4. **Test locally** using `bundle exec jekyll serve`
5. **Commit changes** and push to GitHub
6. **Site updates** automatically via GitHub Pages

## 📝 Contributing

We welcome contributions from the cybersecurity community! Here's how you can help:

### Adding New Threat Actors

1. **Update the database** (`_data/threat_actors.yml`):
   ```yaml
   - name: "Threat Actor Name"
     aliases: ["Alias 1", "Alias 2"]
     description: "Brief description of the threat actor"
     url: "/threat-actor-name"
     country: "Country of Origin"
     sector_focus: ["Sector 1", "Sector 2"]
     first_seen: "YYYY"
     last_activity: "YYYY"
     risk_level: "High|Critical|Medium|Low"
   ```

2. **Create the threat actor page** (`_threat_actors/threat-actor-name.md`):
   ```markdown
   ---
   layout: threat_actor
   title: "Threat Actor Name"
   aliases: ["Alias 1", "Alias 2"]
   description: "Brief description"
   permalink: /threat-actor-name/
   country: "Country"
   sector_focus: ["Sector 1", "Sector 2"]
   first_seen: "YYYY"
   last_activity: "YYYY"
   risk_level: "High"
   ---
   
   ## Introduction
   Detailed introduction about the threat actor...
   
   ## Activities and Tactics
   Information about their activities...
   
   ## Notable Campaigns
   List of major campaigns...
   
   ## Tactics, Techniques, and Procedures (TTPs)
   MITRE ATT&CK techniques...
   
   ## Notable Indicators of Compromise (IOCs)
   IPs, domains, hashes...
   
   ## Malware and Tools
   Associated malware and tools...
   
   ## Attribution and Evidence
   Attribution information...
   
   ## References
   Links to reports and analysis...
   ```

### Updating Existing Information

1. **Edit the YAML data** in `_data/threat_actors.yml`
2. **Update the markdown content** in `_threat_actors/`
3. **Regenerate JSON artifacts** with `ruby scripts/generate-indexes.rb`
4. **Run validation** with `ruby scripts/validate-content.rb`
5. **Test locally** to ensure everything works
6. **Submit a pull request**

### Content Guidelines

- **Accuracy**: Ensure all information is accurate and up-to-date
- **Sources**: Include references and citations
- **Format**: Follow the established content structure
- **Neutrality**: Maintain objective, factual tone
- **Completeness**: Include all available metadata fields

## 🔍 Search and Filtering

The site includes advanced search capabilities:

- **Text Search**: Search by name, aliases, or description
- **Country Filter**: Filter by country of origin
- **Risk Level Filter**: Filter by threat level
- **Sector Filter**: Filter by target sectors
- **Combined Filters**: Use multiple filters simultaneously

## 📊 Data Model

### Threat Actor Fields

| Field | Type | Description | Required |
|-------|------|-------------|----------|
| `name` | String | Primary threat actor name | Yes |
| `aliases` | Array | Alternative names/aliases | Yes |
| `description` | String | Brief description | Yes |
| `url` | String | URL path for the actor | Yes |
| `country` | String | Country of origin | No |
| `sector_focus` | Array | Target sectors | No |
| `first_seen` | String | First observed activity | No |
| `last_activity` | String | Most recent activity | No |
| `risk_level` | String | Threat level (Critical/High/Medium/Low) | No |

### Risk Level Classifications

- **Critical**: Immediate threat, active destructive campaigns
- **High**: Significant threat, regular activity
- **Medium**: Moderate threat, occasional activity
- **Low**: Limited threat, minimal activity

### Generated Artifacts

- `ruby scripts/generate-indexes.rb` reads `_data/threat_actors.yml` and `_threat_actors/*.md`
- `_data/generated/threat_actors.json` stores actor metadata for the UI and API
- `_data/generated/iocs.json` stores a first-pass IOC index extracted from each `## Notable Indicators of Compromise (IOCs)` section
- `_data/generated/facets.json` stores countries, risk levels, sectors, IOC types, and counts for filters
- `_data/generated/campaigns.json` stores flattened campaign entries extracted from `## Notable Campaigns`
- `_data/generated/malware.json` stores flattened malware/tool entries extracted from `## Malware and Tools`
- `_data/generated/attack_mappings.json` stores extracted ATT&CK group and technique mappings
- `_data/generated/references.json` stores flattened references and IOC source links
- `_data/generated/ioc_lookup.json` stores IOC records keyed by normalized value for client-side lookup
- `_data/generated/ioc_types.json` stores a manifest of IOC-type shard endpoints
- `_data/generated/iocs_by_type/*.json` stores IOC shards grouped by IOC type
- `docs/importers.md` documents manual source-import workflows and attribution requirements

## API Endpoints

- `/api/threat-actors.json`: generated actor metadata, page URLs, section headings, and IOC counts
- `/api/iocs.json`: generated IOC records with actor linkage, type, source heading, and normalized value
- `/api/facets.json`: generated filter facets and summary counts used by the search UI
- `/api/campaigns.json`: flattened campaign records with actor linkage and source-section metadata
- `/api/malware.json`: flattened malware/tool records with categories and actor linkage
- `/api/attack-mappings.json`: flattened ATT&CK group and technique mappings with provenance
- `/api/references.json`: flattened references and IOC source links with actor linkage
- `/api/ioc-lookup.json`: normalized IOC lookup object keyed by normalized value, for example `45.32.22.62` or `api-metrics-collector.com`
- `/api/ioc-types.json`: manifest of IOC-type shard endpoints with counts and paths
- `/api/iocs/by-type/<type>.json`: type-specific IOC shard with `records` for practical client-side filtering

IOC records preserve the original heading bucket in `type` and also expose `inferred_type`, `atomic`, `canonical_value`, and `lookup_keys` for more precise querying.
Actor records now also include additive generated structures for `campaigns`, `malware_and_tools`, `attack_mappings`, and `references`.
Actor records may also include optional source provenance fields such as `source_name`, `source_attribution`, `source_record_url`, and `provenance`.

## Source Imports

- `scripts/import-ransomlook.rb` supports fetching, reviewing, and importing RansomLook-derived actor metadata snapshots
- `data/imports/ransomlook/mapping_overrides.yml` stores reviewed rename and alias overrides for bulk import safety
- Importers update canonical inputs only: `_data/threat_actors.yml` and `_threat_actors/*.md`
- Imported content should stay conservative and avoid automatically seeding volatile IOCs into the static API
- See `docs/importers.md` for commands and attribution requirements

## Data Sources

This project aggregates threat actor data from multiple authoritative sources. Each source has specific licensing terms that govern how the data can be used.

### Primary Data Sources

| Source | Description | License | Attribution Required |
|--------|-------------|---------|---------------------|
| **MITRE ATT&CK** | 170+ structured threat groups with aliases, descriptions, and technique mappings | Royalty-free | "© The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation." |
| **MISP Galaxy** | 700+ threat actors with rich metadata (country, victims, sectors) | CC0 1.0 / MIT | Link back to MISP Galaxy |
| **RansomLook** | Ransomware group tracking and victim data | CC BY 4.0 | See docs/importers.md |

### How to Import Data

```bash
# Import MITRE ATT&CK actors (dry-run first)
ruby scripts/import-mitre.rb --dry-run
ruby scripts/import-mitre.rb

# Import with options
ruby scripts/import-mitre.rb --overwrite     # Overwrite existing actors
ruby scripts/import-mitre.rb --include-revoked  # Include deprecated groups
```

### Attribution Requirements

When importing data from external sources, attribution must be preserved:

- **MITRE ATT&CK**: Add `source_attribution` field to imported actors
- **MISP Galaxy**: Link to source in documentation
- **RansomLook**: Follow CC BY 4.0 requirements in docs/importers.md

See `docs/attribution.md` for full licensing details and copyright notices.

## IOC Query Patterns

Because the API is static, queries are done by fetching a helper index and filtering client-side.

```js
const lookup = await fetch('/api/ioc-lookup.json').then((response) => response.json());
const result = lookup['45.32.22.62'];
```

```js
const manifest = await fetch('/api/ioc-types.json').then((response) => response.json());
const shard = await fetch(manifest.ip_address.path).then((response) => response.json());
const matches = shard.records.filter((record) => record.actor_slug === 'apt28');
```

## Validation Workflow

Run these commands before opening a PR:

```bash
ruby scripts/generate-indexes.rb
ruby scripts/validate-content.rb
bundle exec jekyll build --safe
bash scripts/validate.sh
```

## Roadmap

- See `docs/roadmap.md` for phased near-term, medium-term, and longer-term direction
- See `docs/api.md` for endpoint shapes and IOC query examples

## 🛡️ Security Considerations

- **IOC Sanitization**: All IOCs are for educational purposes only
- **No Live Data**: No real-time threat intelligence feeds
- **Attribution**: Information based on public sources and research
- **Disclaimer**: Use information responsibly and verify independently

## 📚 Resources and References

### Threat Intelligence Sources
- [MITRE ATT&CK](https://attack.mitre.org/)
- [CISA Alerts](https://www.cisa.gov/news-events/cybersecurity-advisories)
- [FBI IC3](https://www.ic3.gov/)
- [FireEye Threat Intelligence](https://www.mandiant.com/resources/blog)

### Tools and Frameworks
- [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team)
- [YARA Rules](https://github.com/Yara-Rules/rules)
- [Sigma Rules](https://github.com/SigmaHQ/sigma)

## 🤝 Community

- **Issues**: Report bugs or request features via GitHub Issues
- **Discussions**: Join community discussions
- **Contributions**: Submit pull requests for improvements
- **Feedback**: Share your thoughts and suggestions

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

This project is for educational and research purposes only. The information provided is based on publicly available sources and should not be considered as official threat intelligence. Users are responsible for verifying information independently and using it appropriately.

## 🙏 Acknowledgments

- Cybersecurity researchers and analysts
- Threat intelligence vendors
- Open source security tools
- The broader cybersecurity community

---

**Contributing to ThreatActor.info helps build a stronger, more informed cybersecurity community. Every contribution matters!**
