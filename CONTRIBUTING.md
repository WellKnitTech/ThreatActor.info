# Contributing to ThreatActor.info

Thank you for your interest in contributing to ThreatActor.info! This guide will help you understand how to contribute effectively to our threat intelligence wiki.

## 🤝 How to Contribute

### Types of Contributions

1. **Adding New Threat Actors**
2. **Updating Existing Information**
3. **Improving Content Quality**
4. **Enhancing Features**
5. **Reporting Issues**
6. **Improving Documentation**

## 📋 Getting Started

### Prerequisites

- Basic knowledge of Markdown
- Understanding of YAML syntax
- Git and GitHub account
- Local development environment (optional)

### Development Setup

1. **Fork the repository**
   ```bash
   # Fork on GitHub, then clone your fork
   git clone https://github.com/your-username/threatactor-info.git
   cd threatactor-info
   ```

2. **Install dependencies** (for local testing)
   ```bash
   gem install bundler -v 2.5.10
   bundle install
   ```

3. **Run locally** (optional)
   ```bash
   ruby scripts/generate-indexes.rb
   ruby scripts/validate-content.rb
    bundle exec jekyll serve
   # Visit http://localhost:4000
   ```

---

## ⚡ Add One New Actor (< 2 minutes)

This command adds a new threat actor to `_data/actors/` and generates the page:

```bash
ruby scripts/actor-creator.rb new --name "Name" --alias "Alias1" --alias "Alias2" --country "Country" --description "Brief description"
```

**What it does:**
1. Creates `_data/actors/<url>.yml` with required fields
2. Generates `_threat_actors/<url>.md` from template
3. Runs `generate-indexes.rb` to update JSON artifacts

**Example:**
```bash
ruby scripts/actor-creator.rb new \
  --name "Lazarus Group" \
  --alias "Hidden Cobra" \
  --alias "Guardians of the Peace" \
  --alias "Zinc" \
  --country "KP" \
  --description "North Korea state-sponsored threat actor" \
  --risk-level "Critical" \
  --url "/lazarus-group"
```

**After running:**
- Edit `_data/actors/lazarus-group.yml` to add more fields (sector_focus, first_seen, etc.)
- Edit `_threat_actors/lazarus-group.md` to add detailed content sections
- Run `ruby scripts/validate-content.rb` to verify
- Commit and submit PR

---

## 📖 Documentation References

- **[Schema Reference](docs/schema.md)**: YAML fields, types, and validation rules for threat actor data
- **[Importer Guide](docs/importers.md)**: Source import workflows (MITRE ATT&CK, MISP Galaxy, RansomLook)

## 📝 Content Contribution Guidelines

### Adding New Threat Actors

#### Step 1: Update Source Snapshots

Run source importers first and let the automation update actor shards:

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

#### Step 2: Regenerate Threat Actor Pages

Generate `_threat_actors/*.md` with:
```bash
ruby scripts/generate-pages.rb --force
```

Generated pages follow this structure:

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

## Emulating TTPs with Atomic Red Team
Links to relevant Atomic Red Team tests...

## Malware and Tools
Associated malware and tools...

## Attribution and Evidence
Attribution information...

## References
Links to reports and analysis...

## External Links
- [Wikipedia](https://en.wikipedia.org/wiki/...)
- [MITRE ATT&CK](https://attack.mitre.org/groups/...)
```

### Content Standards

#### Required Information
- **Name**: Primary threat actor name
- **Aliases**: All known aliases and alternative names
- **Description**: Brief, factual description
- **Country**: Country of origin (if known)
- **Sector Focus**: Target sectors and industries
- **Risk Level**: Threat assessment level

#### Content Quality Guidelines

1. **Accuracy**: Ensure all information is accurate and verifiable
2. **Sources**: Include references and citations
3. **Neutrality**: Maintain objective, factual tone
4. **Completeness**: Include all available metadata fields
5. **Format**: Follow the established content structure
6. **Language**: Use clear, professional language

#### Risk Level Classifications

- **Critical**: Immediate threat, active destructive campaigns
- **High**: Significant threat, regular activity
- **Medium**: Moderate threat, occasional activity
- **Low**: Limited threat, minimal activity

### Updating Existing Information

1. **Refresh source snapshots/importers**
2. **Regenerate pages** with `ruby scripts/generate-pages.rb --force`
3. **Regenerate JSON artifacts** with `ruby scripts/generate-indexes.rb`
4. **Run validation** with `ruby scripts/validate-content.rb`
5. **Test locally** to ensure everything works
6. **Submit a pull request**

### Importing Source Snapshots

- Use `ruby scripts/import-ransomlook.rb fetch` to create a local RansomLook snapshot
- Use `ruby scripts/import-ransomlook.rb plan --snapshot ...` before writing anything
- Use `ruby scripts/import-ransomlook.rb import --snapshot ...` only after reviewing the proposed changes
- Keep reviewed rename and alias exceptions in `data/imports/ransomlook/mapping_overrides.yml`
- Keep imported content conservative; do not auto-import volatile IOCs or leak-site infrastructure
- Preserve CC BY 4.0 attribution when using RansomLook-derived data

## 🔧 Technical Contributions

### Code Contributions

1. **Fork the repository**
2. **Create a feature branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```
3. **Make your changes**
4. **Test locally**
5. **Commit your changes**
   ```bash
   git commit -m "Add: Brief description of changes"
   ```
6. **Push to your fork**
   ```bash
   git push origin feature/your-feature-name
   ```
7. **Create a pull request**

### Code Style Guidelines

- **HTML**: Use semantic HTML5 elements
- **CSS**: Follow BEM methodology for class naming
- **JavaScript**: Use modern ES6+ features
- **YAML**: Use consistent indentation (2 spaces)
- **Markdown**: Follow standard Markdown conventions

## 🐛 Reporting Issues

### Bug Reports

When reporting bugs, please include:

1. **Description**: Clear description of the issue
2. **Steps to Reproduce**: How to reproduce the bug
3. **Expected Behavior**: What should happen
4. **Actual Behavior**: What actually happens
5. **Environment**: Browser, OS, device information
6. **Screenshots**: If applicable

### Feature Requests

When requesting features, please include:

1. **Description**: Clear description of the feature
2. **Use Case**: Why this feature would be useful
3. **Proposed Solution**: How you think it should work
4. **Alternatives**: Other solutions you've considered

## 📋 Pull Request Guidelines

### Before Submitting

1. **Test your changes** locally
2. **Check for errors** in the build
3. **Ensure consistency** with existing code
4. **Update documentation** if needed
5. **Add tests** for new features

### Generated Data and API Workflow

- `_threat_actors/` is generated from `_data/actors/*.yml`; avoid manual page edits unless debugging generation logic
- `ruby scripts/generate-indexes.rb` rebuilds actor, IOC, facet, campaign, malware, ATT&CK mapping, reference, IOC lookup, and IOC type-shard artifacts under `_data/generated/`
- The generator also refreshes static query helpers under `api/`, including `/api/ioc-lookup.json`, `/api/ioc-types.json`, and `/api/iocs/by-type/*.json`
- The search UI and static API endpoints under `api/` read those generated artifacts, so regenerate them after content edits
- `ruby scripts/validate-content.rb` now checks collection config, exact section headings, orphan pages, generated JSON parseability, and IOC shard structure
- `docs/api.md` documents the static API response shapes and IOC query patterns for downstream consumers
- `docs/importers.md` documents the manual importer workflow and attribution requirements for source-derived content

### Pull Request Template

```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Documentation update
- [ ] Content addition/update
- [ ] Other (please describe)

## Testing
- [ ] Tested locally
- [ ] No build errors
- [ ] Content verified

## Checklist
- [ ] Code follows style guidelines
- [ ] Self-review completed
- [ ] Documentation updated
- [ ] No breaking changes
```

## 🎯 Contribution Areas

### High Priority

1. **Add Missing Threat Actors**
   - APT groups from different countries
   - Ransomware operations
   - Cybercriminal organizations

2. **Improve Content Quality**
   - Add more detailed TTPs
   - Include more IOCs
   - Add MITRE ATT&CK mappings

3. **Enhance Search Features**
   - Add more filter options
   - Improve search performance
   - Add search suggestions

### Medium Priority

1. **UI/UX Improvements**
   - Better mobile experience
   - Dark mode support
   - Accessibility improvements

2. **Data Quality**
   - Standardize content format
   - Add validation rules
   - Improve data consistency

3. **Documentation**
   - API documentation
   - User guides
   - Developer documentation

## 🛡️ Security and Privacy

### Content Guidelines

- **No Personal Information**: Do not include personal details
- **No Classified Information**: Only use publicly available sources
- **IOC Sanitization**: All IOCs are for educational purposes
- **Attribution**: Always cite sources and references

### Responsible Disclosure

If you discover security vulnerabilities:

1. **Do not** create public issues
2. **Email** security concerns to the maintainers
3. **Wait** for acknowledgment before public disclosure
4. **Follow** responsible disclosure practices

## 📚 Resources

### Learning Resources

- [Jekyll Documentation](https://jekyllrb.com/docs/)
- [Liquid Templating](https://shopify.github.io/liquid/)
- [Markdown Guide](https://www.markdownguide.org/)
- [YAML Syntax](https://yaml.org/spec/1.2/spec.html)

### Threat Intelligence Sources

- [MITRE ATT&CK](https://attack.mitre.org/)
- [CISA Alerts](https://www.cisa.gov/news-events/cybersecurity-advisories)
- [FBI IC3](https://www.ic3.gov/)
- [FireEye Threat Intelligence](https://www.mandiant.com/resources/blog)

## 🤝 Community Guidelines

### Code of Conduct

- **Be Respectful**: Treat everyone with respect
- **Be Inclusive**: Welcome contributors from all backgrounds
- **Be Constructive**: Provide helpful feedback
- **Be Professional**: Maintain professional communication

### Communication

- **GitHub Issues**: For bugs and feature requests
- **GitHub Discussions**: For general questions and ideas
- **Pull Requests**: For code and content contributions
- **Email**: For security concerns

## 🎉 Recognition

Contributors will be recognized in:

- **README**: Listed as contributors
- **Release Notes**: Acknowledged in updates
- **Community**: Featured in community highlights

## 📞 Getting Help

### Questions and Support

- **GitHub Issues**: For technical questions
- **GitHub Discussions**: For general questions
- **Documentation**: Check existing docs first
- **Community**: Ask in discussions

### Contact Maintainers

- **GitHub**: @maintainer-username
- **Email**: maintainer@example.com
- **Twitter**: @threatactorinfo

## 📄 License

By contributing to ThreatActor.info, you agree that your contributions will be licensed under **The Unlicense** (public domain).

---

**Thank you for contributing to ThreatActor.info! Your contributions help build a stronger, more informed cybersecurity community.**
