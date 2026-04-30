#!/usr/bin/env ruby

require 'json'
require 'set'
require 'yaml'

require_relative 'ioc_yaml_reader'

class ContentValidator
  REQUIRED_ACTOR_FIELDS = %w[name aliases description url].freeze
  REQUIRED_FRONT_MATTER_FIELDS = %w[layout title aliases description permalink].freeze
  REQUIRED_SECTION_HEADINGS = [
    'Introduction',
    'Activities and Tactics',
    'Notable Campaigns',
    'Tactics, Techniques, and Procedures (TTPs)',
    'Notable Indicators of Compromise (IOCs)',
    'Malware and Tools',
    'Attribution and Evidence',
    'References'
  ].freeze
  REQUIRED_FILES = [
    '_config.yml',
    '_data/actors/',
    'schemas/threat-actor.schema.json',
    'schemas/generated-array.schema.json',
    'schemas/generated-object.schema.json',
    'schemas/technique.schema.json',
    'schemas/tactic.schema.json',
    'schemas/campaign.schema.json',
    'schemas/mitigation.schema.json',
    'schemas/ioc-shard.schema.json',
    '_layouts/default.html',
    '_layouts/threat_actor.html',
    '_includes/search.html',
    'assets/css/style.scss',
    'index.html',
    'threat-actors.html',
    'scripts/generate-indexes.rb',
    'scripts/evaluate-source-deltas.rb',
    'scripts/import-ransomlook.rb',
    'scripts/validate-json-schemas.rb',
    'scripts/validate-content.rb',
    'scripts/validate.sh',
    'docs/api.md',
    'docs/importers.md',
    'docs/roadmap.md',
    'docs/offline-mitre-bundles.md',
    'docs/new-actor-checklist.md',
    'docs/supersession-backlog.md',
    'api/threat-actors.json',
    'api/iocs.json',
    'api/facets.json',
    'api/recently-updated.json',
    'api/campaigns.json',
    'api/malware.json',
    'api/malware_index.json',
    'api/attack-mappings.json',
    'api/references.json',
    'api/ioc-lookup.json',
    'api/ioc-types.json',
    'api/techniques.json',
    'api/tactics.json',
    'api/mitigations.json',
    'api/campaigns_mitre.json',
    'api/actors_by_technique.json',
    'api/actors_by_tactic.json',
    'api/technique-tactics.json',
    'api/attack-version.json',
    'api/mitre-citation-links.json',
    'api/software_by_actor.json',
    'api/search-index.json',
    'api/ioc-summary.json',
    'api/categorized_adversary_by_group.json',
    'api/categorized_pivot_by_industry.json',
    'api/categorized_pivot_by_motivation.json',
    'api/categorized_pivot_by_victim_country.json',
    'api/categorized_adversary_meta.json',
    'api/actors-by-tactic.json',
    'api/actors-by-technique.json',
    'api/malware-index.json',
    'api/campaigns-mitre.json',
    'api/software-by-actor.json',
    'api/categorized-adversary-by-group.json',
    'api/categorized-pivot-by-industry.json',
    'api/categorized-pivot-by-motivation.json',
    'api/categorized-pivot-by-victim-country.json',
    'api/categorized-adversary-meta.json',
    'api/malware-actor-lookup.json',
    '_layouts/technique.html',
    '_layouts/tactic.html',
    '_layouts/campaign.html',
    '_layouts/mitigation.html',
    '_layouts/ioc_type.html',
    '_includes/ioc-browser.html',
    '_includes/tactic-actors.html',
    'attack-tactics.html',
    'categorized-adversary-ttps.html',
    'iocs/index.html',
    'iocs/ip-address.html',
    'iocs/domain.html',
    'iocs/url.html',
    'iocs/email.html',
    'iocs/md5.html',
    'iocs/sha1.html',
    'iocs/sha256.html',
    'iocs/cve.html',
    'iocs/attack-technique.html',
    'iocs/file-extension.html',
    'iocs/filename.html',
    'iocs/other.html',
    '_data/generated/threat_actors.json',
    '_data/generated/iocs.json',
    '_data/generated/facets.json',
    '_data/generated/recently_updated.json',
    '_data/generated/campaigns.json',
    '_data/generated/malware.json',
    '_data/generated/attack_mappings.json',
    '_data/generated/references.json',
    '_data/generated/ioc_lookup.json',
    '_data/generated/ioc_types.json',
    '_data/generated/malware_index.json',
    '_data/generated/techniques.json',
    '_data/generated/tactics.json',
    '_data/generated/mitigations.json',
    '_data/generated/campaigns_mitre.json',
    '_data/generated/actors_by_technique.json',
    '_data/generated/software_by_actor.json',
    '_data/generated/search_index.json',
    '_data/generated/ioc_summary.json',
    '_data/generated/actors_by_tactic.json',
    '_data/generated/technique_tactics.json',
    '_data/generated/attack_version.json',
    '_data/generated/mitre_citation_links.yml',
    '_data/generated/categorized_adversary_by_group.json',
    '_data/generated/categorized_pivot_by_industry.json',
    '_data/generated/categorized_pivot_by_motivation.json',
    '_data/generated/categorized_pivot_by_victim_country.json',
    '_data/generated/categorized_adversary_meta.json',
    '_data/generated/malware_actor_lookup.json'
  ].freeze
  GENERATED_JSON_FILES = [
    '_data/generated/threat_actors.json',
    '_data/generated/iocs.json',
    '_data/generated/facets.json',
    '_data/generated/recently_updated.json',
    '_data/generated/campaigns.json',
    '_data/generated/malware.json',
    '_data/generated/attack_mappings.json',
    '_data/generated/references.json',
    '_data/generated/ioc_lookup.json',
    '_data/generated/ioc_types.json',
    '_data/generated/malware_index.json',
    '_data/generated/techniques.json',
    '_data/generated/tactics.json',
    '_data/generated/mitigations.json',
    '_data/generated/campaigns_mitre.json',
    '_data/generated/actors_by_technique.json',
    '_data/generated/software_by_actor.json',
    '_data/generated/search_index.json',
    '_data/generated/ioc_summary.json',
    '_data/generated/actors_by_tactic.json',
    '_data/generated/technique_tactics.json',
    '_data/generated/attack_version.json',
    '_data/generated/categorized_adversary_by_group.json',
    '_data/generated/categorized_pivot_by_industry.json',
    '_data/generated/categorized_pivot_by_motivation.json',
    '_data/generated/categorized_pivot_by_victim_country.json',
    '_data/generated/categorized_adversary_meta.json',
    '_data/generated/malware_actor_lookup.json'
  ].freeze
  # Loaded by Jekyll as YAML (not JSON) so GitHub Pages can parse large citation maps.
  GENERATED_YAML_DATA_FILES = [
    '_data/generated/mitre_citation_links.yml'
  ].freeze
  GENERATED_API_WRAPPERS = {
    'api/threat-actors.json' => 'site.data.generated.threat_actors',
    'api/iocs.json' => 'site.data.generated.iocs',
    'api/facets.json' => 'site.data.generated.facets',
    'api/recently-updated.json' => 'site.data.generated.recently_updated',
    'api/campaigns.json' => 'site.data.generated.campaigns',
    'api/malware.json' => 'site.data.generated.malware',
    'api/malware_index.json' => 'site.data.generated.malware_index',
    'api/attack-mappings.json' => 'site.data.generated.attack_mappings',
    'api/references.json' => 'site.data.generated.references',
    'api/ioc-lookup.json' => 'site.data.generated.ioc_lookup',
    'api/ioc-types.json' => 'site.data.generated.ioc_types',
    'api/techniques.json' => 'site.data.generated.techniques',
    'api/tactics.json' => 'site.data.generated.tactics',
    'api/mitigations.json' => 'site.data.generated.mitigations',
    'api/campaigns_mitre.json' => 'site.data.generated.campaigns_mitre',
    'api/actors_by_technique.json' => 'site.data.generated.actors_by_technique',
    'api/actors_by_tactic.json' => 'site.data.generated.actors_by_tactic',
    'api/technique-tactics.json' => 'site.data.generated.technique_tactics',
    'api/attack-version.json' => 'site.data.generated.attack_version',
    'api/mitre-citation-links.json' => 'site.data.generated.mitre_citation_links',
    'api/software_by_actor.json' => 'site.data.generated.software_by_actor',
    'api/search-index.json' => 'site.data.generated.search_index',
    'api/ioc-summary.json' => 'site.data.generated.ioc_summary',
    'api/categorized_adversary_by_group.json' => 'site.data.generated.categorized_adversary_by_group',
    'api/categorized_pivot_by_industry.json' => 'site.data.generated.categorized_pivot_by_industry',
    'api/categorized_pivot_by_motivation.json' => 'site.data.generated.categorized_pivot_by_motivation',
    'api/categorized_pivot_by_victim_country.json' => 'site.data.generated.categorized_pivot_by_victim_country',
    'api/categorized_adversary_meta.json' => 'site.data.generated.categorized_adversary_meta',
    'api/actors-by-tactic.json' => 'site.data.generated.actors_by_tactic',
    'api/actors-by-technique.json' => 'site.data.generated.actors_by_technique',
    'api/malware-index.json' => 'site.data.generated.malware_index',
    'api/campaigns-mitre.json' => 'site.data.generated.campaigns_mitre',
    'api/software-by-actor.json' => 'site.data.generated.software_by_actor',
    'api/categorized-adversary-by-group.json' => 'site.data.generated.categorized_adversary_by_group',
    'api/categorized-pivot-by-industry.json' => 'site.data.generated.categorized_pivot_by_industry',
    'api/categorized-pivot-by-motivation.json' => 'site.data.generated.categorized_pivot_by_motivation',
    'api/categorized-pivot-by-victim-country.json' => 'site.data.generated.categorized_pivot_by_victim_country',
    'api/categorized-adversary-meta.json' => 'site.data.generated.categorized_adversary_meta',
    'api/malware-actor-lookup.json' => 'site.data.generated.malware_actor_lookup'
  }.freeze
  SKIPPED_IOC_HEADINGS = ['Sources'].freeze
  IPV4_PATTERN = /\b(?:\d{1,3}\.){3}\d{1,3}\b/.freeze
  DOMAIN_PATTERN = /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,63}|onion)\b/i.freeze
  EMAIL_PATTERN = /\b[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,63}\b/i.freeze
  URL_PATTERN = %r{\b(?:https?|ftp)://[^\s<>()]+}i.freeze
  FILE_EXTENSION_PATTERN = /\.[a-z0-9]{2,12}\b/i.freeze
  FILENAME_PATTERN = /\b[\w.-]+\.[A-Za-z0-9]{2,12}\b/.freeze
  CVE_PATTERN = /\bCVE-\d{4}-\d{4,7}\b/i.freeze
  ATTACK_TECHNIQUE_PATTERN = /\bT\d{4}(?:\.\d{3})?\b/i.freeze

  def initialize
    @errors = []
    @warnings = []
    @threat_actors_data = []
    @pages = {}
    @config = {}
    @ioc_occurrences = Hash.new { |hash, key| hash[key] = [] }
  end

  def validate_all
    puts 'Starting content validation...'

    validate_required_files
    validate_collection_config
    validate_yaml_data
    load_pages
    validate_threat_actor_pages
    validate_mitre_collection_pages
    validate_orphan_pages
    validate_urls
    validate_source_attribution
    validate_generated_json
    validate_generated_yaml_data_files
    validate_api_wrapper_bindings
    validate_cited_technique_pages
    validate_ioc_shards
    validate_ioc_manifest_pages
    validate_malware_actor_links
    validate_threat_actor_malware_links
    validate_duplicate_ioc_sections

    print_results
    exit_with_code
  end

  private

  def validate_required_files
    puts 'Validating required files...'

    REQUIRED_FILES.each do |file|
      add_error(file, 'Required file missing') unless File.exist?(file)
    end
  end

  def validate_collection_config
    puts 'Validating Jekyll collection config...'

    @config = safe_load_yaml_file('_config.yml') || {}
    collections = @config['collections'] || {}
    threat_actor_collection = collections['threat_actors'] || {}

    unless threat_actor_collection['output'] == true
      add_error('_config.yml', "Collection 'threat_actors' must exist with output: true")
    end

    %w[malware techniques tactics campaigns mitigations].each do |coll|
      cfg = collections[coll] || {}
      unless cfg['output'] == true
        add_error('_config.yml', "Collection '#{coll}' must exist with output: true")
      end
    end
  rescue StandardError => e
    add_error('_config.yml', "Config parsing error: #{e.message}")
  end

  def validate_yaml_data
    puts 'Validating YAML data...'

    actor_files = Dir.glob('_data/actors/*.yml').sort
    if actor_files.empty?
      add_error('_data/actors/', 'No actor YAML files found in _data/actors/')
      @threat_actors_data = []
      return
    end

    @threat_actors_data = []
    actor_files.each do |file|
      begin
        actor = safe_load_yaml_file(file)
        if actor
          @threat_actors_data << actor
          validate_threat_actor_data(actor, file)
        end
      rescue StandardError => e
        add_error(file, "YAML parsing error: #{e.message}")
      end
    end
  end

  def validate_threat_actor_data(actor, file_path)
    REQUIRED_ACTOR_FIELDS.each do |field|
      add_error(file_path, "Missing required field: #{field}") unless actor.key?(field)
    end

    # Check for empty required fields (importer artifacts)
    if actor['aliases'].is_a?(Array) && actor['aliases'].empty?
      add_error(file_path, "Missing required field: aliases (empty array)")
    end
    if actor['description'].is_a?(String) && actor['description'].strip.empty?
      add_error(file_path, "Missing required field: description (empty string)")
    end

    validate_field_types(actor, file_path)
    validate_field_values(actor, file_path)
  end

  def validate_field_types(actor, file_path)
    {
      'name' => String,
      'aliases' => Array,
      'description' => String,
      'url' => String
    }.each do |field, expected_type|
      next unless actor.key?(field)

      unless actor[field].is_a?(expected_type)
        add_error(file_path, "Field '#{field}' must be #{expected_type}, got #{actor[field].class}")
      end
    end
  end

  def validate_field_values(actor, file_path)
    if actor['url'] && !actor['url'].start_with?('/')
      add_error(file_path, "URL must start with '/': #{actor['url']}")
    end

    if actor['risk_level'] && !%w[Critical High Medium Low].include?(actor['risk_level'])
      add_error(file_path, "Invalid risk level: #{actor['risk_level']}")
    end

    if actor['country'] && actor['country'].length < 2
      add_warning(file_path, "Country name seems too short: #{actor['country']}")
    end

    if actor['first_seen'] && !actor['first_seen'].match?(/^\d{4}$/)
      add_warning(file_path, "First seen should be a 4-digit year: #{actor['first_seen']}")
    end

    if actor['last_activity'] && !actor['last_activity'].match?(/^\d{4}$/)
      add_warning(file_path, "Last activity should be a 4-digit year: #{actor['last_activity']}")
    end

    if actor['last_updated'] && !actor['last_updated'].match?(/^\d{4}-\d{2}-\d{2}$/)
      add_warning(file_path, "Last updated should use YYYY-MM-DD format: #{actor['last_updated']}")
    end
  end

  def load_pages
    puts 'Loading threat actor pages...'

    Dir.glob('_threat_actors/*.md').sort.each do |path|
      @pages[path] = parse_page(path)
    rescue StandardError => e
      add_error(path, "Page parsing error: #{e.message}")
    end
  end

  def parse_page(path)
    content = File.read(path)
    match = content.match(/\A---\s*\n(.*?)\n---\s*\n?(.*)\z/m)
    raise 'Missing or invalid front matter' unless match

    {
      content: content,
      front_matter: safe_load_yaml(match[1]) || {},
      body: match[2]
    }
  end

  def validate_mitre_collection_pages
    puts 'Validating MITRE collection pages...'

    missing_attack_version = { '_techniques' => 0, '_tactics' => 0 }
    missing_domains = { '_techniques' => 0, '_tactics' => 0 }

    {
      '_techniques' => 'technique',
      '_tactics' => 'tactic',
      '_campaigns' => 'campaign',
      '_mitigations' => 'mitigation'
    }.each do |dir, expected_layout|
      Dir.glob("#{dir}/*.md").sort.each do |path|
        begin
          page = parse_page(path)
        rescue StandardError => e
          add_error(path, "Page parsing error: #{e.message}")
          next
        end
        fm = page[:front_matter]
        unless fm['layout'] == expected_layout
          add_error(path, "Layout must be '#{expected_layout}', got #{fm['layout'].inspect}")
        end
        add_error(path, 'mitre_id must be present') if fm['mitre_id'].to_s.strip.empty?

        if dir == '_techniques' || dir == '_tactics'
          missing_attack_version[dir] += 1 if fm['attack_version'].to_s.strip.empty?
          missing_domains[dir] += 1 if fm['domains'].to_a.empty? && fm['domain'].to_s.strip.empty?
        end
      end
    end

    %w[_techniques _tactics].each do |dir|
      n = missing_attack_version[dir]
      add_warning(dir, "#{n} #{dir.sub('_', '')} page(s) lack attack_version in front matter (re-import MITRE or add manually)") if n.positive?

      d = missing_domains[dir]
      add_warning(dir, "#{d} #{dir.sub('_', '')} page(s) lack domains/domain in front matter") if d.positive?
    end
  end

  def validate_threat_actor_pages
    puts 'Validating threat actor pages...'

    @threat_actors_data.each do |actor|
      page_path = "_threat_actors#{actor['url']}.md"
      page = @pages[page_path]

      unless page
        add_error(page_path, "Threat actor page not found for #{actor['name']}")
        next
      end

      validate_front_matter(page_path, actor, page[:front_matter])
      validate_required_sections(page_path, page[:body])
      validate_ioc_md_vs_yaml(actor, page_path, page[:body])
      track_ioc_occurrences(page_path, page[:body])
    end
  end

  def validate_front_matter(page_path, actor_data, front_matter)
    REQUIRED_FRONT_MATTER_FIELDS.each do |field|
      add_error(page_path, "Missing required front matter field: #{field}") unless front_matter.key?(field)
    end

    unless front_matter['layout'] == 'threat_actor'
      add_error(page_path, "Layout must be 'threat_actor'")
    end

    expected_permalink = "#{actor_data['url']}/"
    unless front_matter['permalink'] == expected_permalink
      add_error(page_path, "Permalink mismatch. Expected #{expected_permalink}, got #{front_matter['permalink']}")
    end

    unless front_matter['title'] == actor_data['name']
      add_error(page_path, "Title mismatch. Expected #{actor_data['name']}, got #{front_matter['title']}")
    end
  end

  def validate_required_sections(page_path, body)
    headings = body.scan(/^##\s+(.+?)\s*$/).flatten

    REQUIRED_SECTION_HEADINGS.each do |heading|
      unless headings.include?(heading)
        add_error(page_path, "Missing exact required section heading: ## #{heading}")
      end
    end
  end

  def validate_ioc_md_vs_yaml(actor, page_path, body)
    section = extract_section(body, 'Notable Indicators of Compromise (IOCs)')
    return if section.strip.empty?

    atomic = extract_atomic_iocs(section)
    return if atomic.empty?

    merged = IocYamlReader.merged_iocs_sources(actor)
    has_yaml = merged.any? do |_, values|
      Array(values).any? { |value| value.to_s.strip.length.positive? }
    end
    return if has_yaml

    slug = actor['url'].to_s.sub(%r{^/}, '').sub(%r{/$}, '')
    add_warning(
      page_path,
      "Extractable IOC indicators appear in Markdown under ## Notable Indicators of Compromise (IOCs), but _data/actors/#{slug}.yml has no structured IOC entries (add top-level ips/domains/urls/… or nested `iocs:`, or run ruby scripts/migrate-iocs-md-to-yaml.rb --apply)."
    )
  end

  def track_ioc_occurrences(page_path, body)
    ioc_section = extract_section(body, 'Notable Indicators of Compromise (IOCs)')
    return if ioc_section.empty?

    extract_atomic_iocs(ioc_section).each do |ioc|
      key = [ioc[:type], ioc[:normalized_value]]
      @ioc_occurrences[key] << page_path unless @ioc_occurrences[key].include?(page_path)
    end
  end

  def extract_atomic_iocs(section)
    current_heading = 'General'
    seen = {}

    section.each_line.each_with_object([]) do |line, records|
      stripped = line.strip
      next if stripped.empty?

      if stripped.start_with?('### ')
        current_heading = stripped.sub(/^###\s+/, '').strip
        next
      end

      next unless stripped.match?(/^[-*]\s+/)
      next if SKIPPED_IOC_HEADINGS.include?(current_heading)

      content = stripped.sub(/^[-*]\s+/, '').strip
      extract_indicator_candidates(content, current_heading).each do |candidate|
        key = [candidate[:inferred_type], candidate[:normalized_value]].join('|')
        next if candidate[:normalized_value].empty? || seen[key]

        seen[key] = true
        records << { type: candidate[:inferred_type], normalized_value: candidate[:normalized_value] }
      end
    end
  end

  def extract_indicator_candidates(content, heading)
    candidates = []
    normalized_heading = heading.to_s.downcase

    content.scan(/`([^`]+)`/).flatten.each do |value|
      inferred_type = infer_indicator_type(value, normalized_heading)
      next unless inferred_type

      normalized_value = normalize_indicator(value, inferred_type)
      next if normalized_value.empty?

      candidates << { inferred_type: inferred_type, normalized_value: normalized_value }
    end

    plain_text = normalize_text_for_extraction(content)
    candidates.concat(scan_pattern_candidates(plain_text, normalized_heading))
    dedupe_indicator_candidates(candidates)
  end

  def scan_pattern_candidates(content, normalized_heading)
    candidates = []
    candidates.concat(build_indicator_candidates(content.scan(URL_PATTERN), 'url'))
    candidates.concat(build_indicator_candidates(content.scan(EMAIL_PATTERN), 'email'))
    candidates.concat(build_indicator_candidates(content.scan(CVE_PATTERN), 'cve'))
    candidates.concat(build_indicator_candidates(content.scan(ATTACK_TECHNIQUE_PATTERN), 'attack_technique'))
    candidates.concat(build_indicator_candidates(content.scan(IPV4_PATTERN).select { |value| valid_ipv4?(value) }, 'ip_address'))
    candidates.concat(build_indicator_candidates(content.scan(DOMAIN_PATTERN), 'domain'))

    if normalized_heading.include?('file extension')
      candidates.concat(build_indicator_candidates(content.scan(FILE_EXTENSION_PATTERN), 'file_extension'))
    end

    if normalized_heading.include?('ransom') || normalized_heading.include?('note') || normalized_heading.include?('filename')
      candidates.concat(build_indicator_candidates(content.scan(FILENAME_PATTERN), 'filename'))
    end

    candidates
  end

  def build_indicator_candidates(values, inferred_type)
    Array(values).flatten.filter_map do |value|
      normalized_value = normalize_indicator(value, inferred_type)
      next if normalized_value.empty?

      { inferred_type: inferred_type, normalized_value: normalized_value }
    end
  end

  def dedupe_indicator_candidates(candidates)
    seen = {}

    candidates.each_with_object([]) do |candidate, records|
      key = [candidate[:inferred_type], candidate[:normalized_value]].join('|')
      next if seen[key]

      seen[key] = true
      records << candidate
    end
  end

  def infer_indicator_type(value, normalized_heading = nil)
    normalized_value = normalize_text_for_extraction(value)

    return 'sha256' if normalized_value.match?(/\A[a-f0-9]{64}\z/i)
    return 'sha1' if normalized_value.match?(/\A[a-f0-9]{40}\z/i)
    return 'md5' if normalized_value.match?(/\A[a-f0-9]{32}\z/i)
    return 'cve' if normalized_value.match?(CVE_PATTERN)
    return 'attack_technique' if normalized_value.match?(ATTACK_TECHNIQUE_PATTERN)
    return 'url' if normalized_value.match?(URL_PATTERN)
    return 'email' if normalized_value.match?(EMAIL_PATTERN)
    return 'ip_address' if normalized_value.match?(IPV4_PATTERN) && valid_ipv4?(normalized_value)
    return 'file_extension' if normalized_value.match?(/\A\.[a-z0-9]{2,12}\z/i)
    return 'filename' if filename_candidate?(normalized_value, normalized_heading)
    return 'domain' if normalized_value.match?(/\A#{DOMAIN_PATTERN.source}\z/i)

    nil
  end

  def filename_candidate?(value, normalized_heading)
    return false unless value.match?(/\A[\w.-]+\.[A-Za-z0-9]{2,12}\z/)
    return false if value.include?('..')
    return false if value.match?(/\A#{DOMAIN_PATTERN.source}\z/i)

    normalized_heading.to_s.include?('ransom') || normalized_heading.to_s.include?('note') || normalized_heading.to_s.include?('filename')
  end

  def normalize_indicator(value, inferred_type = nil)
    canonical_value = normalize_text_for_extraction(value)
    canonical_value = canonical_value.gsub(/[\]\)>.,;:]+\z/, '')
    canonical_value = canonical_value.gsub(/\A[\[(<"']+/, '')
    canonical_value = canonical_value.gsub(/["']+\z/, '')

    if %w[domain url email file_extension cve attack_technique md5 sha1 sha256].include?(inferred_type)
      canonical_value = canonical_value.downcase
    end

    canonical_value
  end

  def normalize_text_for_extraction(text)
    strip_markdown(text)
      .gsub('[.]', '.')
      .gsub('(.)', '.')
      .gsub('[:]', ':')
      .gsub('[://]', '://')
      .gsub('[@]', '@')
      .gsub(/^hxxps:/i, 'https:')
      .gsub(/^hxxp:/i, 'http:')
      .gsub(/\s+/, ' ')
      .strip
  end

  def valid_ipv4?(value)
    value.split('.').length == 4 && value.split('.').all? { |part| part.to_i.to_s == part && part.to_i.between?(0, 255) }
  end

  def strip_markdown(text)
    text.to_s
      .gsub(/`([^`]+)`/, '\1')
      .gsub(/\*\*([^*]+)\*\*/, '\1')
      .gsub(/\[([^\]]+)\]\([^\)]+\)/, '\1')
      .gsub(/\s+/, ' ')
      .strip
  end

  def validate_orphan_pages
    puts 'Checking for orphan pages...'

    expected_paths = @threat_actors_data.map { |actor| "_threat_actors#{actor['url']}.md" }
    @pages.keys.sort.each do |page_path|
      next if expected_paths.include?(page_path)

      add_error(page_path, 'Orphan threat actor page is not referenced in _data/actors/*.yml')
    end
  end

  def validate_urls
    puts 'Validating URLs and names...'

    urls = @threat_actors_data.map { |actor| actor['url'] }.compact
    names = @threat_actors_data.map { |actor| actor['name'] }.compact

    urls.tally.each do |url, count|
      add_error('_data/actors/*.yml', "Duplicate URL found: #{url}") if count > 1
    end

    names.tally.each do |name, count|
      add_error('_data/actors/*.yml', "Duplicate name found: #{name}") if count > 1
    end
  end

  def validate_source_attribution
    puts 'Validating source attribution consistency...'

    @threat_actors_data.each do |actor|
      actor_name = actor['name'] || 'unknown'
      file_label = "_data/actors/#{actor['url'].to_s.sub(%r{^/}, '')}.yml"
      has_source_signal = !actor['source_name'].to_s.empty? ||
                          !actor['source_record_url'].to_s.empty? ||
                          (actor['provenance'].is_a?(Hash) && !actor['provenance'].empty?)

      next unless has_source_signal

      if actor['source_attribution'].to_s.strip.empty?
        add_warning(file_label, "Actor '#{actor_name}' has source metadata but missing source_attribution")
      end
    end
  end

  def validate_generated_json
    puts 'Validating generated JSON artifacts...'

    GENERATED_JSON_FILES.each do |file|
      unless File.exist?(file)
        add_error(file, 'Generated JSON artifact missing')
        next
      end

      payload = JSON.parse(File.read(file))
      validate_generated_payload_shape(file, payload)
    rescue JSON::ParserError => e
      add_error(file, "Generated JSON is not parseable: #{e.message}")
    rescue StandardError => e
      add_error(file, "Unable to read generated JSON: #{e.message}")
    end
  end

  def validate_generated_yaml_data_files
    puts 'Validating generated YAML data artifacts...'

    GENERATED_YAML_DATA_FILES.each do |file|
      unless File.exist?(file)
        add_error(file, 'Generated YAML data artifact missing')
        next
      end

      payload = YAML.safe_load(File.read(file), permitted_classes: [], aliases: false)
      validate_generated_payload_shape(file, payload)
    rescue Psych::SyntaxError => e
      add_error(file, "Generated YAML is not parseable: #{e.message}")
    rescue StandardError => e
      add_error(file, "Unable to read generated YAML: #{e.message}")
    end
  end

  def validate_generated_payload_shape(file, payload)
    case File.basename(file)
    when 'threat_actors.json', 'recently_updated.json', 'iocs.json', 'campaigns.json', 'malware.json',
         'attack_mappings.json', 'references.json', 'techniques.json', 'tactics.json', 'mitigations.json',
         'campaigns_mitre.json'
      add_error(file, 'Generated JSON root must be an array') unless payload.is_a?(Array)
    when 'facets.json', 'ioc_lookup.json', 'ioc_types.json', 'malware_index.json', 'malware_actor_lookup.json',
         'actors_by_technique.json', 'actors_by_tactic.json', 'technique_tactics.json', 'software_by_actor.json',
         'search_index.json', 'categorized_adversary_by_group.json', 'categorized_pivot_by_industry.json',
         'categorized_pivot_by_motivation.json', 'categorized_pivot_by_victim_country.json'
      add_error(file, 'Generated JSON root must be an object') unless payload.is_a?(Hash)
    when 'ioc_summary.json'
      add_error(file, 'Generated JSON root must be an object') unless payload.is_a?(Hash)
      if payload.is_a?(Hash)
        %w[total_records total_unique_values actor_count_with_iocs type_count].each do |k|
          add_error(file, "ioc_summary.json missing key: #{k}") unless payload.key?(k)
        end
      end
    when 'attack_version.json'
      add_error(file, 'attack_version.json root must be an object') unless payload.is_a?(Hash)
      if payload.is_a?(Hash)
        add_error(file, 'attack_version.json missing active_version') unless payload.key?('active_version')
        if payload['active_version'].to_s.strip.empty?
          add_error(file, 'attack_version.json active_version must be non-empty (run scripts/generate-indexes.rb with MITRE bundles available)')
        end
      end
    when 'mitre_citation_links.yml'
      add_error(file, 'mitre_citation_links.yml root must be an object') unless payload.is_a?(Hash)
      if payload.is_a?(Hash)
        payload.each do |k, v|
          add_error(file, "mitre_citation_links.yml value for #{k.inspect} must be a string URL") unless v.is_a?(String)
        end
      end
    when 'categorized_adversary_meta.json'
      add_error(file, 'categorized_adversary_meta.json root must be an object') unless payload.is_a?(Hash)
      if payload.is_a?(Hash)
        %w[group_count source_repository].each do |k|
          add_error(file, "categorized_adversary_meta.json missing key: #{k}") unless payload.key?(k)
        end
      end
    end
  end

  def validate_cited_technique_pages
    puts 'Validating actor-cited techniques have technique pages...'

    path = '_data/generated/actors_by_technique.json'
    return unless File.exist?(path)

    payload = JSON.parse(File.read(path))
    return unless payload.is_a?(Hash)

    payload.each_key do |tid|
      tid_s = tid.to_s.upcase
      next unless tid_s.match?(/\AT\d{4}(?:\.\d{3})?\z/)

      # Match on-disk filenames: parent techniques use t1234.md; sub-techniques use t1234.001.md
      slug_file = "#{tid_s.downcase}.md"
      md_path = File.join('_techniques', slug_file)
      next if File.exist?(md_path)

      add_error(path, "Technique #{tid_s} is cited by actors but #{md_path} is missing")
    end
  rescue JSON::ParserError => e
    add_error(path, "Unable to parse actors_by_technique.json: #{e.message}")
  rescue StandardError => e
    add_error(path, "Technique page validation failed: #{e.message}")
  end

  def validate_ioc_shards
    puts 'Validating IOC shard artifacts...'

    # Check if there are any IOCs in the generated data
    ioc_file = '_data/generated/iocs.json'
    iocs_exist = File.exist?(ioc_file) && begin
      payload = JSON.parse(File.read(ioc_file))
      payload.is_a?(Array) && !payload.empty?
    rescue
      false
    end

    # Only require shards if IOCs exist
    unless iocs_exist
      puts '  (skipping - no IOCs in data)'
      return
    end

    validate_json_glob('_data/generated/iocs_by_type/*.json', 'generated IOC type shard')
    validate_json_glob('api/iocs/by-type/*.json', 'API IOC type shard')
    validate_ioc_actor_shard_glob('_data/generated/iocs_by_actor/*.json', 'generated IOC actor shard')
    validate_ioc_actor_shard_glob('api/iocs/by-actor/*.json', 'API IOC actor shard')
  end

  IOC_TYPES_WITH_DEDICATED_PAGE = %w[
    ip_address domain url email md5 sha1 sha256 cve attack_technique file_extension filename
  ].freeze

  def validate_ioc_manifest_pages
    puts 'Validating IOC hub vs manifest types...'

    path = '_data/generated/ioc_types.json'
    return unless File.exist?(path)

    manifest = JSON.parse(File.read(path))
    return unless manifest.is_a?(Hash)

    manifest.each_key do |type|
      next if IOC_TYPES_WITH_DEDICATED_PAGE.include?(type)

      add_warning(
        "IOC type #{type}",
        'Rendered via /iocs/other/?ioc_type=… — add iocs/<slug>.html if this subsection becomes common'
      )
    end
  end

  def validate_ioc_actor_shard_glob(pattern, label)
    files = Dir.glob(pattern).sort
    if files.empty?
      add_error(pattern, "Missing #{label} files")
      return
    end

    files.each do |file|
      payload = JSON.parse(File.read(file))
      unless payload.is_a?(Hash) && payload['actor_slug'].is_a?(String) && !payload['actor_slug'].strip.empty? &&
             payload['records'].is_a?(Array) && payload['count'].is_a?(Integer)
        add_error(file, "Invalid #{label} structure (expected actor_slug, count, records)")
      end
    rescue JSON::ParserError => e
      add_error(file, "#{label.capitalize} is not parseable: #{e.message}")
    rescue StandardError => e
      add_error(file, "Unable to read #{label}: #{e.message}")
    end
  end

  def validate_api_wrapper_bindings
    puts 'Validating API wrapper bindings...'

    GENERATED_API_WRAPPERS.each do |path, expected_binding|
      content = File.read(path)
      unless content.include?(expected_binding)
        add_error(path, "API wrapper must reference #{expected_binding}")
      end
    rescue StandardError => e
      add_error(path, "Unable to validate API wrapper binding: #{e.message}")
    end
  end

  def validate_json_glob(pattern, label)
    files = Dir.glob(pattern).sort
    if files.empty?
      add_error(pattern, "Missing #{label} files")
      return
    end

    files.each do |file|
      payload = JSON.parse(File.read(file))
      unless payload.is_a?(Hash) && payload['type'] && payload['records'].is_a?(Array) &&
             payload['grouping'].is_a?(String) && payload['groups'].is_a?(Array) &&
             payload['facets'].is_a?(Hash)
        add_error(file, "Invalid #{label} structure")
      end
    rescue JSON::ParserError => e
      add_error(file, "#{label.capitalize} is not parseable: #{e.message}")
    rescue StandardError => e
      add_error(file, "Unable to read #{label}: #{e.message}")
    end
  end

  def validate_malware_actor_links
    puts 'Validating malware actor links...'

    actor_permalinks = @threat_actors_data.each_with_object(Set.new) do |actor, urls|
      next unless actor['url'].is_a?(String)

      urls << "#{actor['url'].sub(%r{/\z}, '')}/"
    end

    Dir.glob('_malware/*.md').sort.each do |file|
      page = parse_page(file)
      actors = page[:front_matter]['actors']
      next unless actors.is_a?(Array)

      actors.each do |actor|
        name = actor['name'].to_s.strip
        url = actor['url'].to_s.strip

        add_error(file, 'Malware actor entry has blank name') if name.empty?
        add_error(file, "Malware actor '#{name}' has blank URL") if url.empty?
        next if url.empty?

        unless actor_permalinks.include?(url)
          add_error(file, "Malware actor '#{name}' links to unknown actor URL: #{url}")
        end
      end
    end
  end

  def validate_threat_actor_malware_links
    puts 'Validating threat actor malware links...'

    malware_urls = JSON.parse(File.read('_data/generated/malware_index.json')).fetch('malware', []).map { |entry| entry['url'] }.to_set
    Dir.glob('_threat_actors/*.md').sort.each do |file|
      page = parse_page(file)
      section = extract_section(page[:body], 'Malware and Tools')
      next if section.empty?

      extract_malware_names(section).each do |name|
        slug = slugify(name)
        next if slug.empty?

        url = "/malware/#{slug}/"
        add_error(file, "Malware entry '#{name}' does not resolve to #{url}") unless malware_urls.include?(url)
      end
    end
  rescue StandardError => e
    add_error('_data/generated/malware_index.json', "Unable to validate threat actor malware links: #{e.message}")
  end

  def validate_duplicate_ioc_sections
    puts 'Checking for duplicated IOC indicators across pages...'

    @ioc_occurrences.each do |(type, normalized_value), page_paths|
      next if page_paths.length < 2

      sorted_paths = page_paths.sort
      warning = "IOC #{normalized_value.inspect} (#{type}) appears on multiple pages: #{sorted_paths.join(', ')}"
      sorted_paths.each do |page_path|
        add_warning(page_path, warning)
      end
    end
  end

  def extract_section(body, heading)
    pattern = /^##\s+#{Regexp.escape(heading)}\s*$\n?(.*?)(?=^##\s+|\z)/m
    match = body.match(pattern)
    match ? match[1] : ''
  end

  def safe_load_yaml_file(path)
    safe_load_yaml(File.read(path))
  end

  def safe_load_yaml(content)
    YAML.safe_load(content, permitted_classes: [], aliases: false)
  end

  def extract_malware_names(section)
    section.each_line.filter_map do |line|
      stripped = line.strip
      next unless stripped.match?(/^[-*]\s+/)

      content = stripped.sub(/^[-*]\s+/, '').strip
      if (match = content.match(/^\*\*(.+?)\*\*/))
        match[1].strip
      else
        content.gsub(/\[([^\]]+)\]\([^\)]+\)/, '\1').gsub(/[*_`]/, '').strip
      end
    end.reject { |name| name.empty? || name.match?(/information pending/i) }
  end

  def slugify(value)
    value.to_s.downcase.gsub(/[^a-z0-9]+/, '-').gsub(/^-|-$/, '')
  end

  def add_error(file, message)
    @errors << { file: file, message: message }
  end

  def add_warning(file, message)
    @warnings << { file: file, message: message }
  end

  def print_results
    puts
    puts '=' * 60
    puts 'VALIDATION RESULTS'
    puts '=' * 60

    if @errors.empty? && @warnings.empty?
      puts 'All validations passed.'
      return
    end

    unless @errors.empty?
      puts
      puts "ERRORS (#{@errors.length}):"
      @errors.each do |error|
        puts "- #{error[:file]}: #{error[:message]}"
      end
    end

    unless @warnings.empty?
      puts
      puts "WARNINGS (#{@warnings.length}):"
      @warnings.each do |warning|
        puts "- #{warning[:file]}: #{warning[:message]}"
      end
    end

    puts
    puts '=' * 60
  end

  def exit_with_code
    if @errors.empty?
      puts 'Validation completed successfully.'
      exit 0
    else
      puts "Validation failed with #{@errors.length} error(s)."
      exit 1
    end
  end
end

ContentValidator.new.validate_all if __FILE__ == $PROGRAM_NAME
