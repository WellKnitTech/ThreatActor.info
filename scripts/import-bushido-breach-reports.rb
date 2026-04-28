#!/usr/bin/env ruby

# frozen_string_literal: true

require 'digest'
require 'fileutils'
require 'json'
require 'net/http'
require 'optparse'
require 'set'
require 'time'
require 'uri'
require 'yaml'

class BushidoBreachReportsImporter
  DEFAULT_SOURCE_URL = 'https://raw.githubusercontent.com/BushidoUK/Breach-Report-Collection/main/README.md'.freeze
  DEFAULT_SNAPSHOT_ROOT = 'data/imports/bushido-breach-reports'.freeze
  DEFAULT_OVERRIDES_FILE = 'data/imports/bushido-breach-reports/mapping_overrides.yml'.freeze
  SOURCE_NAME = 'BushidoToken Breach Report Collection'.freeze
  SOURCE_REPOSITORY = 'https://github.com/BushidoUK/Breach-Report-Collection'.freeze
  SOURCE_ATTRIBUTION = 'References were identified via the BushidoToken Breach Report Collection (https://github.com/BushidoUK/Breach-Report-Collection), which is used here as a report index. Copyright in linked reports remains with the original publishers.'.freeze

  def initialize(argv)
    @argv = argv.dup
    @command = @argv.shift
    @options = {
      source_url: DEFAULT_SOURCE_URL,
      output: nil,
      snapshot: nil,
      overrides_file: DEFAULT_OVERRIDES_FILE,
      report_json: nil,
      write: false
    }
    @overrides = {
      excluded_reports: Set.new,
      match_overrides: {}
    }
  end

  def run
    case @command
    when 'fetch'
      parse_fetch_options
      fetch_snapshot
    when 'plan'
      parse_import_options
      load_overrides
      import_snapshot
    when 'import'
      parse_import_options
      @options[:write] = true
      load_overrides
      import_snapshot
    else
      puts usage
      exit 1
    end
  end

  private

  def usage
    <<~TEXT
      Usage:
        ruby scripts/import-bushido-breach-reports.rb fetch [options]
        ruby scripts/import-bushido-breach-reports.rb plan --snapshot PATH [options]
        ruby scripts/import-bushido-breach-reports.rb import --snapshot PATH [options]

      Notes:
        - BushidoToken is treated as a breach-report index, not a canonical actor dataset.
        - Unknown, generic, and ambiguous adversary labels require review before import.
        - Imports add provenance to existing actor YAML and append report links to actor pages.
    TEXT
  end

  def parse_fetch_options
    OptionParser.new do |opts|
      opts.banner = 'Usage: ruby scripts/import-bushido-breach-reports.rb fetch [options]'
      opts.on('--source-url URL', 'Bushido README source URL') { |value| @options[:source_url] = value }
      opts.on('--output DIR', 'Snapshot output directory') { |value| @options[:output] = value }
    end.parse!(@argv)

    @options[:output] ||= File.join(DEFAULT_SNAPSHOT_ROOT, Time.now.utc.strftime('%Y-%m-%d'))
  end

  def parse_import_options
    OptionParser.new do |opts|
      opts.banner = 'Usage: ruby scripts/import-bushido-breach-reports.rb plan|import --snapshot PATH [options]'
      opts.on('--snapshot PATH', 'Snapshot directory or README path') { |value| @options[:snapshot] = value }
      opts.on('--overrides PATH', 'Override mapping file') { |value| @options[:overrides_file] = value }
      opts.on('--report-json PATH', 'Write a machine-readable report') { |value| @options[:report_json] = value }
    end.parse!(@argv)

    return if @options[:snapshot]

    warn 'A snapshot path is required for plan/import.'
    exit 1
  end

  def fetch_snapshot
    FileUtils.mkdir_p(@options[:output])
    uri = URI.parse(@options[:source_url])
    response = Net::HTTP.get_response(uri)
    unless response.is_a?(Net::HTTPSuccess)
      warn "HTTP #{response.code} for #{uri}"
      exit 1
    end

    readme_path = File.join(@options[:output], 'README.md')
    manifest_path = File.join(@options[:output], 'manifest.yml')
    File.write(readme_path, response.body)
    File.write(manifest_path, YAML.dump({
                                          'source_name' => SOURCE_NAME,
                                          'source_repository' => SOURCE_REPOSITORY,
                                          'source_url' => @options[:source_url],
                                          'retrieved_at' => Time.now.utc.iso8601,
                                          'source_checksum_sha256' => Digest::SHA256.hexdigest(response.body),
                                          'readme_file' => 'README.md'
                                        }))

    puts "Fetched BushidoToken breach report snapshot into #{@options[:output]}"
  end

  def import_snapshot
    records = parse_records(load_readme)
    actors = load_actors
    actor_index = build_actor_index(actors)
    evaluations = evaluate_records(records, actor_index, actors)
    updates = build_actor_updates(evaluations)
    report = build_report(evaluations, updates)

    File.write(@options[:report_json], JSON.pretty_generate(report) + "\n") if @options[:report_json]
    print_report(report)
    return unless @options[:write]

    apply_updates(updates)
    puts "Applied BushidoToken breach report links to #{updates.length} actors"
  end

  def load_readme
    readme_path = File.directory?(@options[:snapshot]) ? File.join(@options[:snapshot], 'README.md') : @options[:snapshot]
    File.read(readme_path)
  rescue Errno::ENOENT
    warn "Snapshot file not found: #{readme_path}"
    exit 1
  end

  def parse_records(readme)
    readme.each_line.filter_map do |line|
      next unless line.start_with?('|')
      next if line.include?('|---')

      columns = split_markdown_row(line)
      next unless columns.length >= 4
      next if columns[0] == 'Organization'

      {
        'organization' => sanitize_text(columns[0]),
        'breach_date' => sanitize_text(columns[1]),
        'adversary' => sanitize_text(columns[2]),
        'source_cell' => columns[3],
        'links' => extract_links(columns[3]).reject { |link| archive_link?(link['url']) },
        'archived_links' => extract_links(columns[3]).select { |link| archive_link?(link['url']) }
      }
    end
  end

  def split_markdown_row(line)
    line.strip.sub(/^\|/, '').sub(/\|$/, '').split('|').map(&:strip)
  end

  def extract_links(value)
    value.scan(/\[([^\]]+)\]\(([^)]+)\)/).map do |title, url|
      { 'title' => sanitize_text(title), 'url' => sanitize_link(url) }
    end.reject { |link| link['url'].empty? }
  end

  def archive_link?(url)
    url.include?('web.archive.org') || url.include?('archive.is')
  end

  def load_actors
    Dir.glob('_data/actors/*.yml').each_with_object({}) do |path, memo|
      actor = safe_load_yaml_file(path)
      next unless actor && actor['name'] && actor['url']

      memo[actor['name']] = actor.merge('__data_path' => path, '__page_path' => "_threat_actors#{actor['url']}.md")
    end
  end

  def build_actor_index(actors)
    actors.each_value.each_with_object(Hash.new { |hash, key| hash[key] = Set.new }) do |actor, index|
      ([actor['name']] + Array(actor['aliases'])).compact.each do |alias_name|
        normalized = normalize_phrase(alias_name)
        next if normalized.empty?

        index[normalized] << actor['name']
        index[normalized.delete(' ')] << actor['name']
      end
    end
  end

  def evaluate_records(records, actor_index, actors)
    records.filter_map do |record|
      key = report_key(record)
      next if @overrides[:excluded_reports].include?(key)

      matched_names = @overrides[:match_overrides][key] || infer_actor_matches(record, actor_index)
      matched_names = matched_names.select { |name| actors.key?(name) }.uniq
      action = if matched_names.empty?
                 'unmatched'
               elsif @overrides[:match_overrides].key?(key) || matched_names.length == 1
                 'matched'
               else
                 'ambiguous'
               end
      record.merge('report_key' => key, 'matched_actor_names' => matched_names, 'action' => action)
    end
  end

  def infer_actor_matches(record, actor_index)
    adversary_labels(record['adversary']).flat_map do |label|
      normalized = normalize_phrase(label)
      (actor_index[normalized] + actor_index[normalized.delete(' ')]).to_a
    end.uniq
  end

  def adversary_labels(value)
    value
      .gsub(/\([^)]*\)/, '')
      .gsub(/["“”]/, '')
      .split(%r{\s*/\s*})
      .map { |label| sanitize_text(label) }
      .reject { |label| label.empty? || label.match?(/\A(?:unknown|cn apt)\z/i) }
  end

  def build_actor_updates(evaluations)
    evaluations.select { |record| record['action'] == 'matched' }
               .flat_map { |record| record['matched_actor_names'].map { |name| [name, record] } }
               .group_by(&:first)
               .transform_values { |pairs| pairs.map(&:last) }
  end

  def build_report(evaluations, updates)
    {
      timestamp: Time.now.utc.iso8601,
      source: SOURCE_NAME,
      repository: SOURCE_REPOSITORY,
      matched_reports: evaluations.count { |record| record['action'] == 'matched' },
      ambiguous_reports: evaluations.count { |record| record['action'] == 'ambiguous' },
      unmatched_reports: evaluations.count { |record| record['action'] == 'unmatched' },
      actors_with_updates: updates.length,
      actor_updates: updates.map do |actor_name, records|
        {
          name: actor_name,
          report_count: records.length,
          organizations: records.map { |record| record['organization'] }
        }
      end,
      ambiguous_records: evaluations.select { |record| record['action'] == 'ambiguous' },
      unmatched_records: evaluations.select { |record| record['action'] == 'unmatched' }
    }
  end

  def print_report(report)
    puts "\n=== BushidoToken Breach Report Import Plan ==="
    puts "Matched reports: #{report[:matched_reports]}"
    puts "Ambiguous reports: #{report[:ambiguous_reports]}"
    puts "Unmatched reports: #{report[:unmatched_reports]}"
    puts "Actors with updates: #{report[:actors_with_updates]}"
    report[:actor_updates].each do |entry|
      puts "\nUPDATE: #{entry[:name]}"
      puts "  Reports: #{entry[:report_count]}"
      puts "  Organizations: #{entry[:organizations].join(', ')}"
    end
    puts "\n=== Run with import to apply ===" unless @options[:write]
  end

  def apply_updates(updates)
    actors = load_actors
    updates.each do |actor_name, records|
      actor = actors[actor_name]
      next unless actor

      upsert_actor_provenance(actor['__data_path'], records)
      upsert_page_references(actor['__page_path'], records)
    end
  end

  def upsert_actor_provenance(path, records)
    lines = File.readlines(path, chomp: true)
    lines = remove_existing_bushido_provenance(lines)
    block = build_actor_provenance_block(records)
    provenance_index = lines.index { |line| line == 'provenance:' }

    if provenance_index
      lines.insert(provenance_index + 1, *block)
    else
      insert_at = lines.rindex { |line| line.start_with?('source_attribution:') } || lines.length
      lines.insert(insert_at, 'provenance:', *block)
    end

    File.write(path, lines.join("\n") + "\n")
  end

  def remove_existing_bushido_provenance(lines)
    start = lines.index { |line| line == '  bushido_breach_reports:' }
    return lines unless start

    finish = start + 1
    finish += 1 while finish < lines.length && !lines[finish].match?(/\A(?:  [A-Za-z0-9_]+:|[A-Za-z0-9_]+:|---)\s*/)
    lines[0...start] + lines[finish..]
  end

  def build_actor_provenance_block(records)
    rows = [
      '  bushido_breach_reports:',
      "    source_repository: #{quote(SOURCE_REPOSITORY)}",
      "    source_dataset_url: #{quote(@options[:source_url])}",
      "    source_attribution: #{quote(SOURCE_ATTRIBUTION)}",
      "    source_retrieved_at: #{quote(Time.now.utc.strftime('%Y-%m-%dT%H:%M:%SZ'))}",
      '    reports:'
    ]
    records.each do |record|
      rows << "      - organization: #{quote(record['organization'])}"
      rows << "        breach_date: #{quote(record['breach_date'])}"
      rows << "        adversary_label: #{quote(record['adversary'])}"
      rows << "        links: #{record['links'].map { |link| link['url'] }.uniq.to_json}"
      archived_urls = record['archived_links'].map { |link| link['url'] }.uniq
      rows << "        archived_links: #{archived_urls.to_json}" unless archived_urls.empty?
    end
    rows
  end

  def upsert_page_references(path, records)
    return unless File.exist?(path)

    lines = File.readlines(path, chomp: true)
    start = lines.index { |line| line == '## References' }
    return unless start

    finish = start + 1
    finish += 1 while finish < lines.length && !lines[finish].start_with?('## ')
    section = lines[(start + 1)...finish]
    section = remove_existing_bushido_references(section)
    section = [] if section.any? { |line| line.strip == '*References pending cataloguing.*' }
    section << '' unless section.empty? || section.last == ''

    next_id = next_reference_id(section)
    build_page_reference_entries(records, next_id).each { |entry| section.concat(entry) }
    section << '' unless section.last == ''
    lines[(start + 1)...finish] = section
    File.write(path, lines.join("\n") + "\n")
  end

  def remove_existing_bushido_references(section)
    output = []
    skip_indent = false
    section.each do |line|
      if line.include?(SOURCE_NAME)
        skip_indent = true
        next
      end
      if skip_indent && line.start_with?('   ')
        next
      end

      skip_indent = false
      output << line
    end
    output
  end

  def next_reference_id(section)
    ids = section.filter_map { |line| line[/^\[(\d+)\]/, 1]&.to_i }
    (ids.max || 0) + 1
  end

  def build_page_reference_entries(records, next_id)
    entries = []
    records.each do |record|
      record['links'].each do |link|
        title = "#{SOURCE_NAME} - #{record['organization']} breach report"
        title += " (#{record['breach_date']})" unless record['breach_date'].empty?
        title += " via #{link['title']}" unless link['title'].empty?
        entries << [
          "[#{next_id}] [#{title}](#{link['url']})",
          "   Source index: #{SOURCE_REPOSITORY}; adversary label: #{record['adversary']}."
        ]
        next_id += 1
      end
    end
    entries
  end

  def load_overrides
    return unless File.exist?(@options[:overrides_file])

    payload = safe_load_yaml_file(@options[:overrides_file]) || {}
    @overrides[:excluded_reports] = Array(payload['excluded_reports']).map { |value| normalize_key(value) }.to_set
    @overrides[:match_overrides] = (payload['match_overrides'] || {}).each_with_object({}) do |(key, value), memo|
      names = value.is_a?(Array) ? value : [value]
      memo[normalize_key(key)] = names.compact.map(&:to_s)
    end
  end

  def report_key(record)
    normalize_key([record['organization'], record['breach_date'], record['adversary']].join('|'))
  end

  def safe_load_yaml_file(path)
    YAML.safe_load(File.read(path), permitted_classes: [], aliases: true)
  end

  def normalize_phrase(value)
    sanitize_text(value).downcase.gsub(/[^a-z0-9]+/, ' ').strip
  end

  def normalize_key(value)
    normalize_phrase(value).delete(' ')
  end

  def sanitize_text(value)
    value.to_s.gsub(/\s+/, ' ').strip
  end

  def sanitize_link(value)
    value.to_s.strip
  end

  def quote(value)
    value.to_s.to_json
  end
end

BushidoBreachReportsImporter.new(ARGV).run if $PROGRAM_NAME == __FILE__
