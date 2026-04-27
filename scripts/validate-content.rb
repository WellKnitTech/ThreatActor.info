#!/usr/bin/env ruby

begin
  require 'bundler/setup'
rescue LoadError
  nil
end
require 'json'
require 'json_schemer'
require 'set'
require 'yaml'

class ContentValidator
  ACTOR_SCHEMA_FILE = '_schemas/actor.schema.json'.freeze
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
    '_layouts/default.html',
    '_layouts/threat_actor.html',
    '_includes/search.html',
    'assets/css/style.scss',
    'index.html',
    'threat-actors.html',
    'scripts/generate-indexes.rb',
    'scripts/evaluate-source-deltas.rb',
    'scripts/import-ransomlook.rb',
    'scripts/validate-content.rb',
    'scripts/validate.sh',
    ACTOR_SCHEMA_FILE,
    'docs/api.md',
    'docs/importers.md',
    'docs/roadmap.md',
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
    '_data/generated/threat_actors.json',
    '_data/generated/iocs.json',
    '_data/generated/facets.json',
    '_data/generated/recently_updated.json',
    '_data/generated/campaigns.json',
    '_data/generated/malware.json',
    '_data/generated/attack_mappings.json',
    '_data/generated/references.json',
    '_data/generated/ioc_lookup.json',
    '_data/generated/ioc_types.json'
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
    '_data/generated/malware_index.json'
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
    'api/ioc-types.json' => 'site.data.generated.ioc_types'
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
    @actor_schema = nil
  end

  def validate_all
    puts 'Starting content validation...'

    validate_required_files
    validate_collection_config
    validate_yaml_data
    load_pages
    validate_threat_actor_pages
    validate_orphan_pages
    validate_urls
    validate_source_attribution
    validate_generated_json
    validate_api_wrapper_bindings
    validate_ioc_shards
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
          validate_actor_schema(actor, file)
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

  def validate_actor_schema(actor, file_path)
    actor_schema.validate(actor).each do |schema_error|
      pointer = schema_error.fetch('data_pointer', '')
      location = pointer.empty? ? 'record' : pointer.sub(%r{\A/}, '').tr('/', '.')
      add_error(file_path, "Schema violation at #{location}: #{schema_error.fetch('type')}")
    end
  rescue StandardError => e
    add_error(file_path, "Schema validation error: #{e.message}")
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

  def validate_generated_payload_shape(file, payload)
    case File.basename(file)
    when 'threat_actors.json', 'recently_updated.json', 'iocs.json', 'campaigns.json', 'malware.json', 'attack_mappings.json', 'references.json'
      add_error(file, 'Generated JSON root must be an array') unless payload.is_a?(Array)
    when 'facets.json', 'ioc_lookup.json', 'ioc_types.json', 'malware_index.json'
      add_error(file, 'Generated JSON root must be an object') unless payload.is_a?(Hash)
    end
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
      unless payload.is_a?(Hash) && payload.key?('type') && payload.key?('records')
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

  def actor_schema
    @actor_schema ||= JSONSchemer.schema(JSON.parse(File.read(ACTOR_SCHEMA_FILE)))
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
