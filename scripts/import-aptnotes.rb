#!/usr/bin/env ruby

# frozen_string_literal: true

require 'csv'
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
require_relative 'source_precedence'

class AptnotesImporter
  DEFAULT_SOURCE_URL = 'https://raw.githubusercontent.com/aptnotes/data/master/APTnotes.csv'.freeze
  DEFAULT_SNAPSHOT_ROOT = 'data/imports/aptnotes'.freeze
  DEFAULT_OVERRIDES_FILE = 'data/imports/aptnotes/mapping_overrides.yml'.freeze
  SOURCE_NAME = 'APTnotes'.freeze
  SOURCE_REPOSITORY = 'https://github.com/aptnotes/data'.freeze
  SOURCE_ATTRIBUTION = 'References were identified in part via APTnotes (https://github.com/aptnotes/data), which is used here as a report index. Copyright in linked reports remains with the original publishers.'.freeze

  def initialize(argv)
    @argv = argv.dup
    @command = @argv.shift
    @options = {
      source_url: DEFAULT_SOURCE_URL,
      output: nil,
      snapshot: nil,
      actor_filters: [],
      limit: nil,
      overrides_file: DEFAULT_OVERRIDES_FILE,
      report_json: nil,
      write: false
    }
    @overrides = {
      excluded_reports: [],
      match_overrides: {},
      report_overrides: {}
    }
  end

  def run
    case @command
    when 'fetch'
      parse_fetch_options
      load_overrides
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
        ruby scripts/import-aptnotes.rb fetch [options]
        ruby scripts/import-aptnotes.rb plan --snapshot PATH [options]
        ruby scripts/import-aptnotes.rb import --snapshot PATH [options]

      Notes:
        - APTnotes is treated as a report index, not a canonical actor dataset.
        - This importer only enriches existing actors with report-count provenance and year hints.
        - Report-to-actor matching is conservative; ambiguous matches stay review-only.
    TEXT
  end

  def parse_fetch_options
    parser = OptionParser.new do |opts|
      opts.banner = 'Usage: ruby scripts/import-aptnotes.rb fetch [options]'
      opts.on('--source-url URL', 'APTnotes CSV source URL') { |value| @options[:source_url] = value }
      opts.on('--output DIR', 'Snapshot output directory') { |value| @options[:output] = value }
      opts.on('--limit N', Integer, 'Fetch only the first N reports after download') { |value| @options[:limit] = value }
      opts.on('--overrides PATH', 'Override mapping file') { |value| @options[:overrides_file] = value }
    end

    parser.parse!(@argv)
    @options[:output] ||= File.join(DEFAULT_SNAPSHOT_ROOT, Time.now.utc.strftime('%Y-%m-%d'))
  end

  def parse_import_options
    parser = OptionParser.new do |opts|
      opts.banner = 'Usage: ruby scripts/import-aptnotes.rb plan|import --snapshot PATH [options]'
      opts.on('--snapshot PATH', 'Snapshot directory or CSV path') { |value| @options[:snapshot] = value }
      opts.on('--actor NAME', 'Restrict to a specific actor (repeatable)') { |value| @options[:actor_filters] << value }
      opts.on('--limit N', Integer, 'Process only the first N matched actors') { |value| @options[:limit] = value }
      opts.on('--report-json PATH', 'Write a machine-readable report') { |value| @options[:report_json] = value }
      opts.on('--overrides PATH', 'Override mapping file') { |value| @options[:overrides_file] = value }
    end

    parser.parse!(@argv)
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

    rows = CSV.parse(response.body, headers: true)
    rows = rows.first(@options[:limit]) if @options[:limit]

    csv_path = File.join(@options[:output], 'APTnotes.csv')
    manifest_path = File.join(@options[:output], 'manifest.yml')

    File.write(csv_path, CSV.generate do |csv|
      csv << (rows.first&.headers || ['Filename', 'Title', 'Source', 'Link', 'SHA-1', 'Date', 'Year'])
      rows.each { |row| csv << row.fields }
    end)
    File.write(manifest_path, YAML.dump({
                                          'source_name' => SOURCE_NAME,
                                          'source_repository' => SOURCE_REPOSITORY,
                                          'source_url' => @options[:source_url],
                                          'retrieved_at' => Time.now.utc.iso8601,
                                          'record_count' => rows.length,
                                          'source_checksum_sha256' => Digest::SHA256.hexdigest(response.body),
                                          'csv_file' => 'APTnotes.csv'
                                        }))

    puts "Fetched #{rows.length} APTnotes records into #{@options[:output]}"
  end

  def import_snapshot
    records = load_snapshot_records
    existing_actors = ActorStore.load_all
    actor_lookup, actor_slug_lookup, existing_by_name = build_actor_indexes(existing_actors)
    evaluations = evaluate_records(records, actor_lookup, actor_slug_lookup, existing_by_name)
    actor_updates = build_actor_updates(evaluations, existing_by_name)
    actor_updates.select! { |name, _| actor_filter_match?(name) } unless @options[:actor_filters].empty?
    actor_updates = actor_updates.first(@options[:limit]).to_h if @options[:limit]

    report = build_report(evaluations, actor_updates)
    File.write(@options[:report_json], JSON.pretty_generate(report) + "\n") if @options[:report_json]
    print_report(report)

    return unless @options[:write]

    apply_updates(actor_updates, existing_actors)
    ActorStore.save_all(existing_actors)
    puts "Applied APTnotes provenance updates to #{actor_updates.length} actors"
  end

  def load_snapshot_records
    csv_path = if File.directory?(@options[:snapshot])
                 File.join(@options[:snapshot], 'APTnotes.csv')
               else
                 @options[:snapshot]
               end

    CSV.read(csv_path, headers: true).map do |row|
      {
        'filename' => row['Filename'],
        'title' => row['Title'],
        'source' => row['Source'],
        'link' => row['Link'],
        'sha1' => row['SHA-1'],
        'date' => row['Date'],
        'year' => row['Year']
      }
    end
  rescue Errno::ENOENT
    warn "Snapshot file not found: #{csv_path}"
    exit 1
  end

  def build_actor_indexes(existing_actors)
    actor_lookup = Hash.new { |hash, key| hash[key] = Set.new }
    actor_slug_lookup = {}
    existing_by_name = {}

    existing_actors.each do |actor|
      name = actor['name']
      next if name.to_s.empty?

      existing_by_name[name] = actor
      actor_slug_lookup[normalize_key(actor['url'].to_s.sub(%r{^/}, ''))] = name unless actor['url'].to_s.empty?
      actor_aliases(actor).each do |alias_name|
        key = normalize_phrase(alias_name)
        next if key.empty? || skip_alias_for_matching?(key)

        actor_lookup[key] << name
      end
    end

    [actor_lookup, actor_slug_lookup, existing_by_name]
  end

  def actor_aliases(actor)
    ([actor['name']] + Array(actor['aliases'])).map { |value| value.to_s.strip }.reject(&:empty?).uniq
  end

  def skip_alias_for_matching?(value)
    token_count = value.split.length
    return false if value.match?(/\b(?:apt|fin|uac|unc|ta|dev|storm|tag)\b/) || value.match?(/\d/)

    token_count == 1 && value.length < 4
  end

  def evaluate_records(records, actor_lookup, actor_slug_lookup, existing_by_name)
    records.filter_map do |record|
      report_key = override_report_key(record)
      next if @overrides[:excluded_reports].include?(report_key)

      explicit_match = @overrides[:match_overrides][report_key] || @overrides[:report_overrides][report_key]
      matched_names = if explicit_match
                        [explicit_match]
                      else
                        infer_actor_matches(record, actor_lookup, actor_slug_lookup).to_a.sort
                      end

      action = if matched_names.empty?
                 'unmatched'
               elsif matched_names.length == 1 && existing_by_name.key?(matched_names.first)
                 'matched'
               else
                 'ambiguous'
               end

      record.merge('matched_actor_names' => matched_names, 'action' => action)
    end
  end

  def infer_actor_matches(record, actor_lookup, actor_slug_lookup)
    matches = Set.new
    text = [record['title'], record['filename']].compact.join(' ')
    normalized = normalize_phrase(text)
    words = normalized.split

    (1..[6, words.length].min).each do |size|
      words.each_cons(size) do |ngram|
        key = ngram.join(' ')
        next if key.empty?

        actor_lookup[key].each { |name| matches << name }
        matches << actor_slug_lookup[key] if actor_slug_lookup[key]
      end
    end

    matches
  end

  def build_actor_updates(evaluations, existing_by_name)
    grouped = evaluations.select { |record| record['action'] == 'matched' }.group_by { |record| record['matched_actor_names'].first }

    grouped.each_with_object({}) do |(actor_name, records), memo|
      actor = existing_by_name[actor_name]
      next unless actor

      years = records.filter_map { |record| normalize_year(record['year']) }.sort
      sources = records.filter_map { |record| sanitize_text(record['source']) }.uniq.sort
      memo[actor_name] = {
        actor: actor,
        report_count: records.length,
        earliest_report_year: years.first,
        latest_report_year: years.last,
        sources: sources,
        sample_titles: records.first(10).map { |record| sanitize_text(record['title']) },
        links: records.filter_map { |record| sanitize_link(record['link']) }.uniq.first(20)
      }
    end
  end

  def build_report(evaluations, actor_updates)
    {
      timestamp: Time.now.utc.iso8601,
      source: SOURCE_NAME,
      repository: SOURCE_REPOSITORY,
      matched_reports: evaluations.count { |record| record['action'] == 'matched' },
      ambiguous_reports: evaluations.count { |record| record['action'] == 'ambiguous' },
      unmatched_reports: evaluations.count { |record| record['action'] == 'unmatched' },
      actors_with_updates: actor_updates.length,
      actor_updates: actor_updates.map do |actor_name, payload|
        {
          name: actor_name,
          report_count: payload[:report_count],
          earliest_report_year: payload[:earliest_report_year],
          latest_report_year: payload[:latest_report_year],
          sources: payload[:sources],
          sample_titles: payload[:sample_titles]
        }
      end,
      ambiguous_records: evaluations.select { |record| record['action'] == 'ambiguous' }.first(50),
      unmatched_records: evaluations.select { |record| record['action'] == 'unmatched' }.first(50)
    }
  end

  def print_report(report)
    puts "\n=== APTnotes Import Plan ==="
    puts "Matched reports: #{report[:matched_reports]}"
    puts "Ambiguous reports: #{report[:ambiguous_reports]}"
    puts "Unmatched reports: #{report[:unmatched_reports]}"
    puts "Actors with updates: #{report[:actors_with_updates]}"

    report[:actor_updates].first(20).each do |entry|
      puts "\nUPDATE: #{entry[:name]}"
      puts "  Reports: #{entry[:report_count]}"
      puts "  Years: #{entry[:earliest_report_year] || 'N/A'} - #{entry[:latest_report_year] || 'N/A'}"
      puts "  Sources: #{entry[:sources].first(5).join(', ')}"
    end

    puts "\n=== Run with import to apply ===" unless @options[:write]
  end

  def apply_updates(actor_updates, existing_actors)
    existing_by_name = existing_actors.each_with_object({}) { |actor, memo| memo[actor['name']] = actor }

    actor_updates.each do |actor_name, payload|
      actor = existing_by_name[actor_name]
      next unless actor

      actor['provenance'] ||= {}
      actor['provenance']['aptnotes'] = {
        'source_retrieved_at' => Time.now.utc.strftime('%Y-%m-%dT%H:%M:%SZ'),
        'source_dataset_url' => @options[:source_url],
        'source_repository' => SOURCE_REPOSITORY,
        'report_count' => payload[:report_count],
        'earliest_report_year' => payload[:earliest_report_year],
        'latest_report_year' => payload[:latest_report_year],
        'sources' => payload[:sources],
        'sample_titles' => payload[:sample_titles],
        'sample_links' => payload[:links]
      }
      actor['source_name'] ||= SOURCE_NAME
      actor['source_attribution'] ||= SOURCE_ATTRIBUTION
      actor['first_seen'] ||= payload[:earliest_report_year] if payload[:earliest_report_year]
      actor['last_activity'] ||= payload[:latest_report_year] if payload[:latest_report_year]
    end
  end

  def actor_filter_match?(actor_name)
    filters = @options[:actor_filters].map { |value| normalize_key(value) }
    filters.include?(normalize_key(actor_name))
  end

  def override_report_key(record)
    [record['sha1'], record['filename'], record['title']].map { |value| normalize_key(value) }.find { |value| !value.empty? } || ''
  end

  def load_overrides
    return unless File.exist?(@options[:overrides_file])

    payload = safe_load_yaml_file(@options[:overrides_file]) || {}
    @overrides[:excluded_reports] = Array(payload['excluded_reports']).map { |value| normalize_key(value) }.uniq
    @overrides[:match_overrides] = normalize_override_hash(payload['match_overrides'], preserve_values: true)
    @overrides[:report_overrides] = normalize_override_hash(payload['report_overrides'], preserve_values: true)
  end

  def normalize_override_hash(value, preserve_values: false)
    (value || {}).each_with_object({}) do |(key, mapped_value), memo|
      normalized_key = normalize_key(key)
      next if normalized_key.empty?

      memo[normalized_key] = preserve_values ? mapped_value : normalize_key(mapped_value)
    end
  end

  def normalize_phrase(value)
    sanitize_text(value).downcase.gsub(/[^a-z0-9]+/, ' ').strip
  end

  def normalize_key(value)
    normalize_phrase(value).gsub(' ', '')
  end

  def sanitize_text(value)
    value.to_s.gsub(/\s+/, ' ').strip
  end

  def normalize_year(value)
    match = value.to_s.match(/\A(19|20)\d{2}\z/)
    match && match[0]
  end

  def sanitize_link(value)
    link = sanitize_text(value)
    return nil unless link.match?(%r{\Ahttps?://}i)

    link
  end

  def safe_load_yaml_file(path)
    YAML.safe_load(File.read(path), permitted_classes: [], aliases: false)
  end
end

AptnotesImporter.new(ARGV).run if __FILE__ == $PROGRAM_NAME
