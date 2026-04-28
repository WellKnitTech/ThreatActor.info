#!/usr/bin/env ruby
# frozen_string_literal: true

require 'digest'
require 'fileutils'
require 'json'
require 'net/http'
require 'optparse'
require 'time'
require 'uri'
require 'yaml'

class CuratedIntelMoveitTransferImporter
  DEFAULT_SOURCE_URL = 'https://raw.githubusercontent.com/curated-intel/MOVEit-Transfer/main/README.md'.freeze
  DEFAULT_SNAPSHOT_ROOT = 'data/imports/curated-intel-moveit-transfer'.freeze
  SOURCE_NAME = 'Curated Intelligence MOVEit Transfer Tracking'.freeze
  SOURCE_REPOSITORY = 'https://github.com/curated-intel/MOVEit-Transfer'.freeze
  SOURCE_ATTRIBUTION = 'MOVEit Transfer campaign events were reviewed from the Curated Intelligence MOVEit Transfer tracking repository (https://github.com/curated-intel/MOVEit-Transfer). Linked reports remain owned by their original publishers.'.freeze
  TARGET_ACTOR_NAME = 'Cl0p'.freeze
  TARGET_ACTOR_PATH = '_data/actors/cl0p.yml'.freeze
  TARGET_PAGE_PATH = '_threat_actors/cl0p.md'.freeze

  MONTHS = {
    'January' => '01',
    'February' => '02',
    'March' => '03',
    'April' => '04',
    'May' => '05',
    'June' => '06',
    'July' => '07',
    'August' => '08',
    'September' => '09',
    'October' => '10',
    'November' => '11',
    'December' => '12'
  }.freeze

  def initialize(argv)
    @argv = argv.dup
    @command = @argv.shift
    @options = {
      source_url: DEFAULT_SOURCE_URL,
      output: nil,
      snapshot: nil,
      report_json: nil,
      write: false
    }
  end

  def run
    case @command
    when 'fetch'
      parse_fetch_options
      fetch_snapshot
    when 'plan'
      parse_import_options
      import_snapshot
    when 'import'
      parse_import_options
      @options[:write] = true
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
        ruby scripts/import-curated-intel-moveit-transfer.rb fetch [options]
        ruby scripts/import-curated-intel-moveit-transfer.rb plan --snapshot PATH [options]
        ruby scripts/import-curated-intel-moveit-transfer.rb import --snapshot PATH [options]

      Notes:
        - Imports the curated MOVEit Transfer campaign event table into the Cl0p actor.
        - Adds source provenance, a page timeline, and source references.
    TEXT
  end

  def parse_fetch_options
    OptionParser.new do |opts|
      opts.banner = 'Usage: ruby scripts/import-curated-intel-moveit-transfer.rb fetch [options]'
      opts.on('--source-url URL', 'Curated Intelligence README source URL') { |value| @options[:source_url] = value }
      opts.on('--output DIR', 'Snapshot output directory') { |value| @options[:output] = value }
    end.parse!(@argv)

    @options[:output] ||= File.join(DEFAULT_SNAPSHOT_ROOT, Time.now.utc.strftime('%Y-%m-%d'))
  end

  def parse_import_options
    OptionParser.new do |opts|
      opts.banner = 'Usage: ruby scripts/import-curated-intel-moveit-transfer.rb plan|import --snapshot PATH [options]'
      opts.on('--snapshot PATH', 'Snapshot directory or README path') { |value| @options[:snapshot] = value }
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
    File.write(readme_path, response.body)
    File.write(File.join(@options[:output], 'manifest.yml'), YAML.dump({
      'source_name' => SOURCE_NAME,
      'source_repository' => SOURCE_REPOSITORY,
      'source_url' => @options[:source_url],
      'retrieved_at' => Time.now.utc.iso8601,
      'source_checksum_sha256' => Digest::SHA256.hexdigest(response.body),
      'readme_file' => 'README.md'
    }))

    puts "Fetched Curated Intelligence MOVEit Transfer snapshot into #{@options[:output]}"
  end

  def import_snapshot
    records = parse_records(load_readme)
    report = build_report(records)
    FileUtils.mkdir_p(File.dirname(@options[:report_json])) if @options[:report_json]
    File.write(@options[:report_json], JSON.pretty_generate(report) + "\n") if @options[:report_json]
    print_report(report)
    return unless @options[:write]

    upsert_actor_provenance(records)
    upsert_page_timeline(records)
    puts "Applied #{records.length} MOVEit Transfer campaign events to #{TARGET_ACTOR_NAME}"
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
      next if line.include?('| ---') || line.include?('Publish Date')

      columns = split_markdown_row(line)
      next unless columns.length >= 4

      source_links = extract_links(columns[3])
      {
        'publish_date' => normalize_date(columns[0]),
        'event_type' => sanitize_text(columns[1]),
        'description' => sanitize_text(strip_markdown_links(columns[2])),
        'source_title' => source_links.first&.fetch('title', nil) || sanitize_text(columns[3]),
        'source_url' => source_links.first&.fetch('url', nil) || sanitize_link(columns[3])
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

  def strip_markdown_links(value)
    value.gsub(/\[([^\]]+)\]\(([^)]+)\)/, '\1')
  end

  def normalize_date(value)
    text = sanitize_text(value)
    return text if text.match?(/\d{4}/)

    day, month = text.split(/\s+/, 2)
    month_number = MONTHS[month]
    return "#{text} 2023" unless day && month_number

    "2023-#{month_number}-#{day.rjust(2, '0')}"
  end

  def build_report(records)
    {
      timestamp: Time.now.utc.iso8601,
      source: SOURCE_NAME,
      repository: SOURCE_REPOSITORY,
      target_actor: TARGET_ACTOR_NAME,
      event_count: records.length,
      event_types: records.map { |record| record['event_type'] }.tally.sort.to_h,
      unique_sources: records.map { |record| record['source_url'] }.reject(&:empty?).uniq.length
    }
  end

  def print_report(report)
    puts "\n=== Curated Intelligence MOVEit Transfer Import Plan ==="
    puts "Target actor: #{report[:target_actor]}"
    puts "Events: #{report[:event_count]}"
    puts "Unique sources: #{report[:unique_sources]}"
    report[:event_types].each { |type, count| puts "  #{type}: #{count}" }
    puts "\n=== Run with import to apply ===" unless @options[:write]
  end

  def upsert_actor_provenance(records)
    lines = File.readlines(TARGET_ACTOR_PATH, chomp: true)
    lines = remove_existing_provenance(lines)
    block = build_actor_provenance_block(records)
    provenance_index = lines.index { |line| line == 'provenance:' }

    if provenance_index
      lines.insert(provenance_index + 1, *block)
    else
      insert_at = lines.rindex { |line| line.start_with?('source_attribution:') } || lines.length
      lines.insert(insert_at + 1, 'provenance:', *block)
    end

    File.write(TARGET_ACTOR_PATH, lines.join("\n") + "\n")
  end

  def remove_existing_provenance(lines)
    start = lines.index { |line| line == '  curated_intel_moveit_transfer:' }
    return lines unless start

    finish = start + 1
    finish += 1 while finish < lines.length && !lines[finish].match?(/\A(?:  [A-Za-z0-9_]+:|[A-Za-z0-9_]+:|---)\s*/)
    lines[0...start] + lines[finish..]
  end

  def build_actor_provenance_block(records)
    rows = [
      '  curated_intel_moveit_transfer:',
      "    source_name: #{quote(SOURCE_NAME)}",
      "    source_repository: #{quote(SOURCE_REPOSITORY)}",
      "    source_dataset_url: #{quote(@options[:source_url] || DEFAULT_SOURCE_URL)}",
      "    source_attribution: #{quote(SOURCE_ATTRIBUTION)}",
      "    source_retrieved_at: #{quote(Time.now.utc.strftime('%Y-%m-%dT%H:%M:%SZ'))}",
      "    event_count: #{records.length}",
      '    events:'
    ]
    records.each do |record|
      rows << "      - publish_date: #{quote(record['publish_date'])}"
      rows << "        event_type: #{quote(record['event_type'])}"
      rows << "        description: #{quote(record['description'])}"
      rows << "        source_title: #{quote(record['source_title'])}"
      rows << "        source_url: #{quote(record['source_url'])}"
    end
    rows
  end

  def upsert_page_timeline(records)
    lines = File.readlines(TARGET_PAGE_PATH, chomp: true)
    start = lines.index { |line| line == '## Notable Campaigns' }
    return unless start

    finish = start + 1
    finish += 1 while finish < lines.length && !lines[finish].start_with?('## ')
    lines[start...finish] = build_campaign_section(records)
    File.write(TARGET_PAGE_PATH, lines.join("\n") + "\n")
  end

  def build_campaign_section(records)
    rows = [
      '## Notable Campaigns',
      '### MOVEit Transfer campaign timeline',
      "#{SOURCE_NAME} tracks #{records.length} public events for the 2023 MOVEit Transfer hacking campaign attributed to CL0P/Lace Tempest.",
      '',
      '| Date | Type | Event | Source |',
      '|---|---|---|---|'
    ]
    records.each do |record|
      source = source_link(record)
      rows << "| #{escape_table_cell(record['publish_date'])} | #{escape_table_cell(record['event_type'])} | #{escape_table_cell(record['description'])} | #{source} |"
    end
    rows << ''
    rows
  end

  def source_link(record)
    title = record['source_title'].to_s.empty? ? 'source' : record['source_title']
    url = record['source_url'].to_s
    url.empty? ? escape_table_cell(title) : "[#{escape_table_cell(title)}](#{url})"
  end

  def escape_table_cell(value)
    sanitize_text(value).gsub('|', '&#124;')
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

CuratedIntelMoveitTransferImporter.new(ARGV).run if $PROGRAM_NAME == __FILE__
