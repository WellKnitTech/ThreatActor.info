#!/usr/bin/env ruby
# frozen_string_literal: true

require 'digest'
require 'fileutils'
require 'json'
require 'net/http'
require 'nokogiri'
require 'optparse'
require 'set'
require 'time'
require 'uri'
require 'yaml'

require_relative 'actor_store'
require_relative 'import_utils'

class Unit42ThreatActorGroupsImporter
  DEFAULT_SNAPSHOT_ROOT = 'data/imports/unit42-threat-actor-groups'.freeze
  SOURCE_NAME = 'Palo Alto Networks Unit 42 Threat Actor Groups'.freeze
  SOURCE_URL = 'https://unit42.paloaltonetworks.com/threat-actor-groups-tracked-by-palo-alto-networks-unit-42/'.freeze
  SOURCE_ATTRIBUTION = 'Aliases were reviewed from Palo Alto Networks Unit 42 threat actor group index and preserved with source provenance.'.freeze

  def initialize(argv)
    @argv = argv.dup
    @command = @argv.shift
    @options = { output: nil, snapshot: nil, report_json: nil, write: false }
  end

  def run
    case @command
    when 'fetch'
      parse_fetch_options
      fetch_snapshot
    when 'plan'
      parse_import_options
      plan_or_import
    when 'import'
      parse_import_options
      @options[:write] = true
      plan_or_import
    else
      warn usage
      exit 1
    end
  end

  private

  def usage
    <<~TEXT
      Usage: ruby scripts/import-unit42-threat-actor-groups.rb fetch|plan|import [options]
    TEXT
  end

  def parse_fetch_options
    OptionParser.new do |opts|
      opts.banner = 'Usage: ruby scripts/import-unit42-threat-actor-groups.rb fetch [options]'
      opts.on('--output DIR', 'Snapshot directory') { |value| @options[:output] = value }
    end.parse!(@argv)
    @options[:output] ||= File.join(DEFAULT_SNAPSHOT_ROOT, Time.now.utc.strftime('%Y-%m-%d'))
  end

  def parse_import_options
    OptionParser.new do |opts|
      opts.banner = 'Usage: ruby scripts/import-unit42-threat-actor-groups.rb plan|import --snapshot DIR [options]'
      opts.on('--snapshot DIR', 'Snapshot directory') { |value| @options[:snapshot] = value }
      opts.on('--report-json PATH', 'Write JSON report') { |value| @options[:report_json] = value }
    end.parse!(@argv)
    abort 'Missing --snapshot' if @options[:snapshot].to_s.empty?
  end

  def fetch_snapshot
    FileUtils.mkdir_p(@options[:output])
    html = http_get(SOURCE_URL)
    actors = parse_actors_from_html(html)

    File.write(File.join(@options[:output], 'page.html'), html)
    File.write(File.join(@options[:output], 'actors.json'), JSON.pretty_generate(actors))
    manifest = {
      'source_name' => SOURCE_NAME,
      'source_url' => SOURCE_URL,
      'retrieved_at' => Time.now.utc.iso8601,
      'source_checksum_sha256' => Digest::SHA256.hexdigest(html),
      'record_count' => actors.length
    }
    File.write(File.join(@options[:output], 'manifest.yml'), YAML.dump(manifest))
    puts "Wrote snapshot to #{@options[:output]} (#{actors.length} parsed records)"
  end

  def parse_actors_from_html(html)
    doc = Nokogiri::HTML(html)
    text_lines = doc.css('article p, article li, article td, article th, main p, main li, main td, main th').map { |n| n.text.strip }.reject(&:empty?)

    records = text_lines.flat_map { |line| extract_names_from_line(line) }
    normalize_records(records)
  end

  def extract_names_from_line(line)
    cleaned = line.gsub(/[\u2013\u2014]/, '-').gsub(/\s+/, ' ').strip
    return [] if cleaned.length < 4

    matches = []
    if cleaned =~ /\A([A-Za-z0-9 .\-]+?)\s*\((?:aka|AKA)\s+([^\)]+)\)/
      primary = Regexp.last_match(1).strip
      aliases = Regexp.last_match(2).split(/[\/,;]|\bor\b/i).map(&:strip).reject(&:empty?)
      matches << { 'name' => primary, 'aliases' => aliases }
    elsif cleaned =~ /\A([A-Za-z0-9 .\-]+?)\s*[:-]\s*([A-Za-z].+)/
      name = Regexp.last_match(1).strip
      tail = Regexp.last_match(2).strip
      return [] if name.split.length > 6
      matches << { 'name' => name, 'aliases' => tail.scan(/\b[A-Z][A-Za-z0-9\-]{2,}\b/).uniq.first(5) }
    end
    matches
  end

  def normalize_records(records)
    grouped = {}
    records.each do |record|
      name = normalize_name(record['name'])
      next if name.empty?

      grouped[name] ||= Set.new
      Array(record['aliases']).each do |alias_name|
        normalized_alias = normalize_name(alias_name)
        grouped[name] << normalized_alias unless normalized_alias.empty? || normalized_alias.casecmp?(name)
      end
    end

    grouped.map do |name, aliases|
      { 'name' => name, 'aliases' => aliases.to_a.sort }
    end.sort_by { |entry| entry['name'].downcase }
  end

  def normalize_name(value)
    value.to_s.gsub(/[\u2018\u2019]/, "'").gsub(/[\u201C\u201D]/, '"').gsub(/\s+/, ' ').strip
  end

  def plan_or_import
    manifest = load_manifest
    entries = load_entries
    existing = ActorStore.load_all
    alias_index = ImportUtils.build_alias_index(existing)

    updates = entries.filter_map do |entry|
      actor = ImportUtils.find_actor_by_names(alias_index, [entry['name'], *Array(entry['aliases'])])
      next unless actor

      {
        actor_name: actor['name'],
        data_path: actor['__data_path'],
        source_name: entry['name'],
        aliases: Array(entry['aliases'])
      }
    end

    report = {
      timestamp: Time.now.utc.iso8601,
      source: SOURCE_NAME,
      source_url: SOURCE_URL,
      source_retrieved_at: manifest['retrieved_at'],
      parsed_records: entries.length,
      actors_with_updates: updates.length,
      updates: updates.sort_by { |row| row[:actor_name] }
    }

    puts JSON.pretty_generate(report)
    File.write(@options[:report_json], JSON.pretty_generate(report)) if @options[:report_json]
    apply_updates(updates, manifest) if @options[:write]
  end

  def apply_updates(updates, manifest)
    updates.each do |update|
      actor = YAML.safe_load(File.read(update[:data_path]), permitted_classes: [], aliases: true) || {}
      actor['aliases'] = (Array(actor['aliases']) + update[:aliases]).uniq.sort
      actor['provenance'] ||= {}
      actor['provenance']['unit42_threat_actor_groups'] = {
        'source_name' => SOURCE_NAME,
        'source_dataset_url' => SOURCE_URL,
        'source_retrieved_at' => manifest['retrieved_at'] || Time.now.utc.iso8601,
        'source_record_id' => update[:source_name]
      }
      actor['source_name'] ||= SOURCE_NAME
      actor['source_attribution'] ||= SOURCE_ATTRIBUTION
      File.write(update[:data_path], YAML.dump(actor))
    end
  end

  def load_manifest
    path = File.join(@options[:snapshot], 'manifest.yml')
    abort "Missing #{path}" unless File.exist?(path)

    YAML.safe_load(File.read(path), permitted_classes: [Time], aliases: true) || {}
  end

  def load_entries
    path = File.join(@options[:snapshot], 'actors.json')
    abort "Missing #{path}" unless File.exist?(path)

    JSON.parse(File.read(path))
  end

  def http_get(url)
    uri = URI.parse(url)
    Net::HTTP.start(uri.host, uri.port, use_ssl: uri.scheme == 'https') do |http|
      req = Net::HTTP::Get.new(uri)
      req['User-Agent'] = 'ThreatActor.info importer'
      res = http.request(req)
      raise "HTTP #{res.code} for #{url}" unless res.is_a?(Net::HTTPSuccess)

      res.body
    end
  end
end

Unit42ThreatActorGroupsImporter.new(ARGV).run
