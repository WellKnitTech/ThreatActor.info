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
require_relative 'actor_store'

class RansomwareToolMatrixImporter
  DEFAULT_SNAPSHOT_ROOT = 'data/imports/ransomware-tool-matrix'.freeze
  DEFAULT_OVERRIDES_FILE = 'data/imports/ransomware-tool-matrix/mapping_overrides.yml'.freeze
  SOURCE_NAME = 'BushidoUK Ransomware Tool Matrix'.freeze
  SOURCE_REPOSITORY = 'https://github.com/BushidoUK/Ransomware-Tool-Matrix'.freeze
  SOURCE_TREE_URL = 'https://api.github.com/repos/BushidoUK/Ransomware-Tool-Matrix/git/trees/main?recursive=1'.freeze
  RAW_BASE_URL = 'https://raw.githubusercontent.com/BushidoUK/Ransomware-Tool-Matrix/main'.freeze
  SOURCE_ATTRIBUTION = 'Tool observations were reviewed from the BushidoUK Ransomware Tool Matrix (https://github.com/BushidoUK/Ransomware-Tool-Matrix). The matrix is used here as a secondary ransomware tradecraft reference, not as sole attribution evidence.'.freeze

  CATEGORY_LABELS = {
    'RMM-Tools.md' => 'RMM Tools',
    'Exfiltration.md' => 'Exfiltration',
    'CredentialTheft.md' => 'Credential Theft',
    'DefenseEvasion.md' => 'Defense Evasion',
    'Networking.md' => 'Networking',
    'DiscoveryEnum.md' => 'Discovery',
    'Offsec.md' => 'OffSec',
    'LOLBAS.md' => 'LOLBAS'
  }.freeze

  ROLE_MARKERS = {
    leading_star: 'initial_access_broker',
    trailing_star: 'ransomware_affiliate',
    trailing_plus: 'state_sponsored_ransomware'
  }.freeze

  def initialize(argv)
    @argv = argv.dup
    @command = @argv.shift
    @options = {
      output: nil,
      snapshot: nil,
      actor_filters: [],
      limit: nil,
      overrides_file: DEFAULT_OVERRIDES_FILE,
      report_json: nil,
      write: false
    }
    @overrides = {
      excluded_labels: Set.new,
      match_overrides: {},
      tool_drop_list: Set.new
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
        ruby scripts/import-ransomware-tool-matrix.rb fetch [options]
        ruby scripts/import-ransomware-tool-matrix.rb plan --snapshot PATH [options]
        ruby scripts/import-ransomware-tool-matrix.rb import --snapshot PATH [options]

      Notes:
        - Enriches existing actors only; it does not create new actors.
        - Imports stable tool/category observations and source references into provenance.
        - Matching overrides should be reviewed before broad imports.
    TEXT
  end

  def parse_fetch_options
    OptionParser.new do |opts|
      opts.banner = 'Usage: ruby scripts/import-ransomware-tool-matrix.rb fetch [options]'
      opts.on('--output DIR', 'Snapshot output directory') { |value| @options[:output] = value }
    end.parse!(@argv)

    @options[:output] ||= File.join(DEFAULT_SNAPSHOT_ROOT, Time.now.utc.strftime('%Y-%m-%d'))
  end

  def parse_import_options
    OptionParser.new do |opts|
      opts.banner = 'Usage: ruby scripts/import-ransomware-tool-matrix.rb plan|import --snapshot PATH [options]'
      opts.on('--snapshot PATH', 'Snapshot directory') { |value| @options[:snapshot] = value }
      opts.on('--actor NAME', 'Restrict to a specific actor (repeatable)') { |value| @options[:actor_filters] << value }
      opts.on('--limit N', Integer, 'Process only the first N matched actors') { |value| @options[:limit] = value }
      opts.on('--overrides PATH', 'Override mapping file') { |value| @options[:overrides_file] = value }
      opts.on('--report-json PATH', 'Write a machine-readable report') { |value| @options[:report_json] = value }
    end.parse!(@argv)

    return if @options[:snapshot]

    warn 'A snapshot path is required for plan/import.'
    exit 1
  end

  def fetch_snapshot
    FileUtils.mkdir_p(@options[:output])
    tree = JSON.parse(http_get(URI.parse(SOURCE_TREE_URL)))
    paths = tree.fetch('tree', []).map { |entry| entry['path'] }.select { |path| snapshot_file?(path) }.sort
    checksums = {}

    paths.each do |path|
      body = http_get(URI.parse("#{RAW_BASE_URL}/#{path}"))
      local_path = File.join(@options[:output], path)
      FileUtils.mkdir_p(File.dirname(local_path))
      File.write(local_path, body)
      checksums[path] = Digest::SHA256.hexdigest(body)
    end

    manifest = {
      'source_name' => SOURCE_NAME,
      'source_repository' => SOURCE_REPOSITORY,
      'source_url' => SOURCE_TREE_URL,
      'raw_base_url' => RAW_BASE_URL,
      'retrieved_at' => Time.now.utc.iso8601,
      'file_count' => paths.length,
      'checksums_sha256' => checksums
    }
    File.write(File.join(@options[:output], 'manifest.yml'), YAML.dump(manifest))
    puts "Fetched #{paths.length} Ransomware Tool Matrix files into #{@options[:output]}"
  rescue JSON::ParserError => e
    warn "Invalid GitHub tree response: #{e.message}"
    exit 1
  end

  def snapshot_file?(path)
    path == 'README.md' ||
      path.start_with?('Tools/') ||
      path.start_with?('GroupProfiles/') ||
      path.start_with?('CommunityReports/') ||
      path.start_with?('ThreatIntel/')
  end

  def import_snapshot
    records, manifest = load_snapshot
    actors = ActorStore.load_all
    actor_index, actors_by_name = build_actor_index(actors)
    candidates, evaluated = build_candidates(records, actor_index, actors_by_name)
    candidates.select! { |candidate| actor_filter_match?(candidate[:actor_name]) } unless @options[:actor_filters].empty?
    candidates = candidates.first(@options[:limit]) if @options[:limit]

    report = build_report(evaluated, candidates, manifest)
    File.write(@options[:report_json], JSON.pretty_generate(report) + "\n") if @options[:report_json]
    print_report(report)
    return unless @options[:write]

    apply_candidates(candidates, actors, manifest)
    puts "Applied Ransomware Tool Matrix enrichments to #{candidates.length} actors"
  end

  def load_snapshot
    manifest_path = File.join(@options[:snapshot], 'manifest.yml')
    manifest = File.exist?(manifest_path) ? safe_load_yaml_file(manifest_path) : {}
    records = Hash.new { |hash, key| hash[key] = empty_record(key) }

    load_tool_tables(records)
    load_group_profiles(records)
    load_community_reports(records)
    load_threat_intel(records)

    [records.values.reject { |record| @overrides[:excluded_labels].include?(record[:label_key]) }, manifest]
  end

  def empty_record(label)
    normalized = normalize_matrix_label(label)
    {
      label: normalized[:label],
      label_key: normalized[:key],
      roles: normalized[:roles],
      tools_by_category: Hash.new { |hash, key| hash[key] = Set.new },
      source_files: Set.new,
      references: {},
      community_reports: []
    }
  end

  def load_tool_tables(records)
    CATEGORY_LABELS.each do |filename, category|
      path = File.join(@options[:snapshot], 'Tools', filename)
      next unless File.exist?(path)

      parse_markdown_table(File.read(path)).each do |row|
        tool = sanitize_text(row['Tool Name'])
        next if tool.empty?

        split_actor_labels(row['Threat Group Usage']).each do |label|
          record = records[label]
          record[:tools_by_category][category] << tool
          record[:source_files] << "Tools/#{filename}"
        end
      end
    end
  end

  def load_group_profiles(records)
    Dir.glob(File.join(@options[:snapshot], 'GroupProfiles', '*.md')).sort.each do |path|
      relative_path = relative_snapshot_path(path)
      body = File.read(path)
      label = group_profile_label(path, body)
      record = records[label]
      record[:source_files] << relative_path

      parse_markdown_table(body).each do |row|
        CATEGORY_LABELS.values.each do |category|
          split_tool_cell(row[category]).each { |tool| record[:tools_by_category][category] << tool }
        end

        report = row['Report']
        date = sanitize_text(row['Date Published'])
        next if report.to_s.empty?

        extract_links(report).each do |link|
          record[:references][link[:url]] ||= {
            title: link[:title],
            url: link[:url],
            date: date,
            source_file: relative_path
          }
        end
      end
    end
  end

  def load_community_reports(records)
    Dir.glob(File.join(@options[:snapshot], 'CommunityReports', 'CR-*.md')).sort.each do |path|
      relative_path = relative_snapshot_path(path)
      body = File.read(path)
      label = body[/Named adversary:\s*([^\n]+)/, 1]
      next if label.to_s.strip.empty?

      record = records[label]
      record[:source_files] << relative_path
      record[:community_reports] << community_report_summary(body, relative_path)

      parse_markdown_table(body).each do |row|
        CATEGORY_LABELS.values.each do |category|
          split_tool_cell(row[category]).each { |tool| record[:tools_by_category][category] << tool }
        end

        extract_links(row['Report']).each do |link|
          record[:references][link[:url]] ||= {
            title: link[:title],
            url: link[:url],
            date: sanitize_text(row['Date Published']),
            source_file: relative_path
          }
        end
      end
    end
  end

  def load_threat_intel(records)
    Dir.glob(File.join(@options[:snapshot], 'ThreatIntel', '*.md')).sort.each do |path|
      relative_path = relative_snapshot_path(path)
      parse_markdown_table(File.read(path)).each do |row|
        label = row['Ransomware/Extortionist'] || row['Threat Group'] || row['Group']
        next if label.to_s.strip.empty?

        record = records[label]
        record[:source_files] << relative_path
        report = row['#StopRansomware Report'] || row['Report'] || row['Source']
        extract_links(report).each do |link|
          record[:references][link[:url]] ||= {
            title: link[:title],
            url: link[:url],
            date: sanitize_text(row['Date Published']),
            source_file: relative_path
          }
        end
      end
    end
  end

  def build_candidates(records, actor_index, actors_by_name)
    evaluated = records.filter_map do |record|
      next if record[:tools_by_category].empty? && record[:references].empty? && record[:community_reports].empty?

      matches = @overrides[:match_overrides][record[:label_key]] || actor_index[record[:label_key]].to_a
      matches = matches.select { |name| actors_by_name.key?(name) }.uniq
      action = if matches.empty?
                 'unmatched'
               elsif matches.length == 1
                 'update'
               else
                 'review'
               end
      record.merge(action: action, matched_actor_names: matches)
    end

    updates = evaluated.select { |candidate| candidate[:action] == 'update' }
    merged = updates.group_by { |candidate| candidate[:matched_actor_names].first }.map do |actor_name, actor_records|
      merge_actor_records(actor_name, actor_records)
    end

    [merged.sort_by { |candidate| candidate[:actor_name].downcase }, evaluated]
  end

  def merge_actor_records(actor_name, records)
    merged = empty_record(records.first[:label])
    merged[:source_labels] = records.map { |record| record[:label] }.uniq.sort
    merged[:label] = merged[:source_labels].join(' / ')
    merged[:label_key] = normalize_key(merged[:label])
    merged[:records] = records
    records.each do |record|
      record[:roles].each { |role| merged[:roles] << role }
      record[:source_files].each { |source_file| merged[:source_files] << source_file }
      record[:community_reports].each { |community_report| merged[:community_reports] << community_report }
      record[:references].each { |url, reference| merged[:references][url] ||= reference }
      record[:tools_by_category].each do |category, tools|
        tools.each { |tool| merged[:tools_by_category][category] << tool }
      end
    end
    merged.merge(action: 'update', actor_name: actor_name, matched_actor_names: [actor_name], records: records)
  end

  def apply_candidates(candidates, actors, manifest)
    actors_by_name = actors.each_with_object({}) { |actor, memo| memo[actor['name']] = actor }
    candidates.each do |candidate|
      actor = actors_by_name[candidate[:actor_name]]
      next unless actor

      actor['provenance'] = {} unless actor['provenance'].is_a?(Hash)
      actor['provenance']['ransomware_tool_matrix'] = provenance_payload(candidate, manifest)
      actor['last_updated'] = Time.now.utc.strftime('%Y-%m-%d')
      path = File.join(ActorStore::ACTORS_DIR, "#{ActorStore.slug_for(actor['url'])}.yml")
      File.write(path, ActorStore.serialize_actor(actor))
    end
  end

  def provenance_payload(candidate, manifest)
    {
      'source_repository' => SOURCE_REPOSITORY,
      'source_dataset_url' => SOURCE_TREE_URL,
      'source_attribution' => SOURCE_ATTRIBUTION,
      'source_retrieved_at' => manifest['retrieved_at'] || Time.now.utc.iso8601,
      'source_label' => candidate[:label],
      'actor_roles' => candidate[:roles].to_a.sort,
      'source_files' => candidate[:source_files].to_a.sort,
      'tools_by_category' => candidate[:tools_by_category].transform_values { |tools| tools.to_a.sort }.sort.to_h,
      'references' => candidate[:references].values.sort_by { |ref| [ref[:date].to_s, ref[:title].to_s] }.map do |ref|
        {
          'title' => ref[:title],
          'url' => ref[:url],
          'date' => ref[:date],
          'source_file' => ref[:source_file]
        }.reject { |_key, value| value.to_s.empty? }
      end,
      'community_reports' => candidate[:community_reports].uniq
    }.reject { |_key, value| value.respond_to?(:empty?) && value.empty? }
  end

  def build_actor_index(actors)
    index = Hash.new { |hash, key| hash[key] = Set.new }
    by_name = {}
    actors.each do |actor|
      name = actor['name'].to_s
      by_name[name] = actor
      ([name] + Array(actor['aliases'])).compact.each do |label|
        key = normalize_key(label)
        next if key.empty?

        index[key] << name
      end
    end
    [index, by_name]
  end

  def build_report(records, candidates, manifest)
    updated_label_keys = candidates.flat_map { |candidate| candidate[:records].map { |record| record[:label_key] } }.to_set
    unmatched = records.reject { |record| updated_label_keys.include?(record[:label_key]) }

    {
      timestamp: Time.now.utc.iso8601,
      source: SOURCE_NAME,
      repository: SOURCE_REPOSITORY,
      retrieved_at: manifest['retrieved_at'],
      source_records: records.length,
      actors_with_updates: candidates.length,
      actor_updates: candidates.map do |candidate|
        {
          name: candidate[:actor_name],
          source_labels: candidate[:source_labels],
          tool_count: candidate[:tools_by_category].values.sum(&:length),
          categories: candidate[:tools_by_category].keys.sort,
          reference_count: candidate[:references].length,
          community_report_count: candidate[:community_reports].length
        }
      end,
      unmatched_labels: unmatched.map { |record| record[:label] }.sort
    }
  end

  def print_report(report)
    puts "\n=== Ransomware Tool Matrix Import Plan ==="
    puts "Source records: #{report[:source_records]}"
    puts "Actors with updates: #{report[:actors_with_updates]}"
    report[:actor_updates].each do |entry|
      puts "\nUPDATE: #{entry[:name]} (#{entry[:source_labels].join(', ')})"
      puts "  Tools: #{entry[:tool_count]} across #{entry[:categories].join(', ')}"
      puts "  References: #{entry[:reference_count]}"
      puts "  Community reports: #{entry[:community_report_count]}"
    end
    puts "\nUnmatched labels: #{report[:unmatched_labels].length}"
    puts "\n=== Run with import to apply ===" unless @options[:write]
  end

  def parse_markdown_table(body)
    tables = []
    lines = body.each_line.map(&:chomp)
    lines.each_with_index do |line, index|
      next unless line.start_with?('|')
      next unless lines[index + 1].to_s.match?(/\A\|?\s*:?-{3,}/)

      headers = split_markdown_row(line)
      cursor = index + 2
      while cursor < lines.length && lines[cursor].start_with?('|')
        values = split_markdown_row(lines[cursor])
        tables << headers.each_with_index.to_h { |header, offset| [sanitize_text(header), sanitize_text(values[offset])] }
        cursor += 1
      end
    end
    tables
  end

  def split_markdown_row(line)
    line.strip.sub(/\A\|/, '').sub(/\|\z/, '').split('|').map(&:strip)
  end

  def split_actor_labels(value)
    sanitize_text(value).split(/\s*,\s*/).map(&:strip).reject(&:empty?)
  end

  def split_tool_cell(value)
    sanitize_text(value).split(%r{\s*<br\s*/?>\s*}i).map(&:strip).reject do |tool|
      tool.empty? || @overrides[:tool_drop_list].include?(normalize_key(tool))
    end
  end

  def group_profile_label(path, body)
    title = body[/^#\s+(.+?)'s Tools\s*$/, 1]
    title ||= File.basename(path, '.md')
    title.gsub(/([a-z])([A-Z])/, '\1 \2').tr('_', ' ')
  end

  def community_report_summary(body, relative_path)
    {
      'source_file' => relative_path,
      'incident_time' => sanitize_text(body[/Time of Incident:\s*([^\n]+)/, 1]),
      'victim_sector' => sanitize_text(body[/Victim Sector:\s*([^\n]+)/, 1]),
      'victim_country' => sanitize_text(body[/Victim Country:\s*([^\n]+)/, 1])
    }.reject { |_key, value| value.to_s.empty? }
  end

  def extract_links(value)
    text = value.to_s
    links = text.scan(/\[([^\]]+)\]\(([^)]+)\)/).map do |title, url|
      { title: sanitize_text(title), url: sanitize_link(url) }
    end
    bare_urls = text.scan(%r{https?://[^\s)<|]+}).map { |url| { title: host_title(url), url: sanitize_link(url) } }
    (links + bare_urls).uniq { |link| link[:url] }.reject { |link| link[:url].empty? }
  end

  def normalize_matrix_label(label)
    text = sanitize_text(label)
    roles = Set.new
    roles << ROLE_MARKERS[:leading_star] if text.start_with?('*')
    roles << ROLE_MARKERS[:trailing_star] if text.end_with?('*')
    roles << ROLE_MARKERS[:trailing_plus] if text.end_with?('+')
    clean = text.sub(/\A\*/, '').sub(/[*+]\z/, '').gsub(/\([^)]*\)/, '').strip
    { label: clean, key: normalize_key(clean), roles: roles }
  end

  def actor_filter_match?(actor_name)
    @options[:actor_filters].any? { |filter| normalize_key(filter) == normalize_key(actor_name) }
  end

  def load_overrides
    return unless File.exist?(@options[:overrides_file])

    payload = safe_load_yaml_file(@options[:overrides_file]) || {}
    @overrides[:excluded_labels] = Array(payload['excluded_labels']).map { |value| normalize_key(value) }.to_set
    @overrides[:tool_drop_list] = Array(payload['tool_drop_list']).map { |value| normalize_key(value) }.to_set
    @overrides[:match_overrides] = (payload['match_overrides'] || {}).each_with_object({}) do |(key, value), memo|
      memo[normalize_key(key)] = Array(value).map(&:to_s)
    end
  end

  def http_get(uri, limit = 5)
    raise "Too many redirects for #{uri}" if limit <= 0

    response = Net::HTTP.get_response(uri)
    case response
    when Net::HTTPSuccess
      response.body
    when Net::HTTPRedirection
      http_get(URI.parse(response['location']), limit - 1)
    else
      raise "HTTP #{response.code} for #{uri}"
    end
  end

  def safe_load_yaml_file(path)
    YAML.safe_load(File.read(path), permitted_classes: [], aliases: true)
  end

  def relative_snapshot_path(path)
    path.sub(%r{\A#{Regexp.escape(@options[:snapshot])}/?}, '')
  end

  def normalize_key(value)
    sanitize_text(value).downcase.gsub(/[^a-z0-9]+/, '')
  end

  def sanitize_text(value)
    value.to_s.gsub(/\s+/, ' ').strip
  end

  def sanitize_link(value)
    value.to_s.strip
  end

  def host_title(url)
    URI.parse(url).host || url
  rescue URI::InvalidURIError
    url
  end
end

RansomwareToolMatrixImporter.new(ARGV).run if $PROGRAM_NAME == __FILE__
