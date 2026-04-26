#!/usr/bin/env ruby

require 'json'
require 'yaml'

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
    '_data/threat_actors.yml',
    '_layouts/default.html',
    '_layouts/threat_actor.html',
    '_includes/search.html',
    'assets/css/style.scss',
    'index.html',
    'threat-actors.html',
    'scripts/generate-indexes.rb',
    'scripts/import-ransomlook.rb',
    'scripts/validate-content.rb',
    'scripts/validate.sh',
    'docs/api.md',
    'docs/importers.md',
    'docs/roadmap.md',
    'api/threat-actors.json',
    'api/iocs.json',
    'api/facets.json',
    'api/campaigns.json',
    'api/malware.json',
    'api/attack-mappings.json',
    'api/references.json',
    'api/ioc-lookup.json',
    'api/ioc-types.json',
    '_data/generated/threat_actors.json',
    '_data/generated/iocs.json',
    '_data/generated/facets.json',
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
    '_data/generated/campaigns.json',
    '_data/generated/malware.json',
    '_data/generated/attack_mappings.json',
    '_data/generated/references.json',
    '_data/generated/ioc_lookup.json',
    '_data/generated/ioc_types.json'
  ].freeze

  def initialize
    @errors = []
    @warnings = []
    @threat_actors_data = []
    @pages = {}
    @config = {}
    @ioc_section_signatures = {}
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
    validate_generated_json
    validate_ioc_shards
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

    @threat_actors_data = safe_load_yaml_file('_data/threat_actors.yml')
    unless @threat_actors_data.is_a?(Array)
      add_error('_data/threat_actors.yml', 'Root element must be an array')
      @threat_actors_data = []
      return
    end

    @threat_actors_data.each_with_index do |actor, index|
      validate_threat_actor_data(actor, index)
    end
  rescue StandardError => e
    add_error('_data/threat_actors.yml', "YAML parsing error: #{e.message}")
    @threat_actors_data = []
  end

  def load_pages
    puts 'Loading threat actor pages...'

    Dir.glob('_threat_actors/*.md').sort.each do |path|
      @pages[path] = parse_page(path)
    rescue StandardError => e
      add_error(path, "Page parsing error: #{e.message}")
    end
  end

  def validate_threat_actor_data(actor, index)
    REQUIRED_ACTOR_FIELDS.each do |field|
      add_error("_data/threat_actors.yml[#{index}]", "Missing required field: #{field}") unless actor.key?(field)
    end

    validate_field_types(actor, index)
    validate_field_values(actor, index)
  end

  def validate_field_types(actor, index)
    {
      'name' => String,
      'aliases' => Array,
      'description' => String,
      'url' => String
    }.each do |field, expected_type|
      next unless actor.key?(field)

      unless actor[field].is_a?(expected_type)
        add_error("_data/threat_actors.yml[#{index}]", "Field '#{field}' must be #{expected_type}, got #{actor[field].class}")
      end
    end
  end

  def validate_field_values(actor, index)
    if actor['url'] && !actor['url'].start_with?('/')
      add_error("_data/threat_actors.yml[#{index}]", "URL must start with '/': #{actor['url']}")
    end

    if actor['risk_level'] && !%w[Critical High Medium Low].include?(actor['risk_level'])
      add_error("_data/threat_actors.yml[#{index}]", "Invalid risk level: #{actor['risk_level']}")
    end

    if actor['country'] && actor['country'].length < 2
      add_warning("_data/threat_actors.yml[#{index}]", "Country name seems too short: #{actor['country']}")
    end

    if actor['first_seen'] && !actor['first_seen'].match?(/^\d{4}$/)
      add_warning("_data/threat_actors.yml[#{index}]", "First seen should be a 4-digit year: #{actor['first_seen']}")
    end

    if actor['last_activity'] && !actor['last_activity'].match?(/^\d{4}$/)
      add_warning("_data/threat_actors.yml[#{index}]", "Last activity should be a 4-digit year: #{actor['last_activity']}")
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
      track_ioc_section_signature(page_path, page[:body])
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

  def track_ioc_section_signature(page_path, body)
    ioc_section = extract_section(body, 'Notable Indicators of Compromise (IOCs)')
    return if ioc_section.empty?

    signature = ioc_section.each_line.map { |line| normalize_ioc_line(line) }.reject(&:empty?).join("\n")
    return if signature.empty?

    @ioc_section_signatures[page_path] = signature
  end

  def validate_orphan_pages
    puts 'Checking for orphan pages...'

    expected_paths = @threat_actors_data.map { |actor| "_threat_actors#{actor['url']}.md" }
    @pages.keys.sort.each do |page_path|
      next if expected_paths.include?(page_path)

      add_error(page_path, 'Orphan threat actor page is not referenced in _data/threat_actors.yml')
    end
  end

  def validate_urls
    puts 'Validating URLs and names...'

    urls = @threat_actors_data.map { |actor| actor['url'] }.compact
    names = @threat_actors_data.map { |actor| actor['name'] }.compact

    urls.tally.each do |url, count|
      add_error('_data/threat_actors.yml', "Duplicate URL found: #{url}") if count > 1
    end

    names.tally.each do |name, count|
      add_error('_data/threat_actors.yml', "Duplicate name found: #{name}") if count > 1
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
    when 'threat_actors.json', 'iocs.json', 'campaigns.json', 'malware.json', 'attack_mappings.json', 'references.json'
      add_error(file, 'Generated JSON root must be an array') unless payload.is_a?(Array)
    when 'facets.json', 'ioc_lookup.json', 'ioc_types.json'
      add_error(file, 'Generated JSON root must be an object') unless payload.is_a?(Hash)
    end
  end

  def validate_ioc_shards
    puts 'Validating IOC shard artifacts...'

    validate_json_glob('_data/generated/iocs_by_type/*.json', 'generated IOC type shard')
    validate_json_glob('api/iocs/by-type/*.json', 'API IOC type shard')
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

  def validate_duplicate_ioc_sections
    puts 'Checking for duplicated IOC sections across pages...'

    grouped = @ioc_section_signatures.group_by { |_path, signature| signature }
    grouped.each_value do |entries|
      next if entries.length < 2

      page_paths = entries.map(&:first).sort
      page_paths.each do |page_path|
        add_warning(page_path, "IOC section content is duplicated across pages: #{page_paths.join(', ')}")
      end
    end
  end

  def extract_section(body, heading)
    pattern = /^##\s+#{Regexp.escape(heading)}\s*$\n?(.*?)(?=^##\s+|\z)/m
    match = body.match(pattern)
    match ? match[1] : ''
  end

  def normalize_ioc_line(line)
    line.to_s
      .downcase
      .gsub(/\[([^\]]+)\]\([^\)]+\)/, '\1')
      .gsub(/\s+/, ' ')
      .strip
  end

  def safe_load_yaml_file(path)
    safe_load_yaml(File.read(path))
  end

  def safe_load_yaml(content)
    YAML.safe_load(content, permitted_classes: [], aliases: false)
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
