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
require_relative 'actor_store'

class BreachHQThreatActorsImporter
  DEFAULT_SNAPSHOT_ROOT = 'data/imports/breach-hq-threat-actors'.freeze
  SOURCE_NAME = 'BreachHQ Threat Actors'.freeze
  SOURCE_URL = 'https://breach-hq.com/threat-actors'.freeze
  HTML_FILE = 'threat-actors.html'.freeze
  JSON_FILE = 'threat-actors.json'.freeze

  def initialize(argv)
    @argv = argv.dup
    @command = @argv.shift
    @options = { output: nil, snapshot: nil, report_json: nil, write: false }
  end

  def run
    case @command
    when 'fetch' then parse_fetch_options && fetch_snapshot
    when 'plan' then parse_import_options && import_snapshot
    when 'import' then parse_import_options && @options[:write] = true && import_snapshot
    else
      warn usage
      exit 1
    end
  end

  private

  def usage
    "Usage: ruby scripts/import-breach-hq-threat-actors.rb fetch|plan|import [options]"
  end

  def parse_fetch_options
    OptionParser.new do |opts|
      opts.on('--output DIR') { |v| @options[:output] = v }
    end.parse!(@argv)
    @options[:output] ||= File.join(DEFAULT_SNAPSHOT_ROOT, Time.now.utc.strftime('%Y-%m-%d'))
  end

  def parse_import_options
    OptionParser.new do |opts|
      opts.on('--snapshot PATH') { |v| @options[:snapshot] = v }
      opts.on('--report-json PATH') { |v| @options[:report_json] = v }
    end.parse!(@argv)
    return if @options[:snapshot]

    warn 'A snapshot path is required for plan/import.'
    exit 1
  end

  def fetch_snapshot
    FileUtils.mkdir_p(@options[:output])
    html = http_get(URI.parse(SOURCE_URL))
    html_path = File.join(@options[:output], HTML_FILE)
    File.binwrite(html_path, html)
    actors = extract_actors(html)
    File.write(File.join(@options[:output], JSON_FILE), JSON.pretty_generate({ 'actors' => actors }) + "\n")
    manifest = {
      'source_name' => SOURCE_NAME,
      'source_url' => SOURCE_URL,
      'retrieved_at' => Time.now.utc.iso8601,
      'record_count' => actors.length,
      'license_status' => 'Use as a secondary research index with preserved source attribution; verify terms and linked reports independently.',
      'checksums_sha256' => {
        HTML_FILE => Digest::SHA256.file(html_path).hexdigest,
        JSON_FILE => Digest::SHA256.file(File.join(@options[:output], JSON_FILE)).hexdigest
      }
    }
    File.write(File.join(@options[:output], 'manifest.yml'), YAML.dump(manifest))
    puts "Fetched #{actors.length} BreachHQ threat actor rows into #{@options[:output]}"
  end

  def import_snapshot
    snapshot = @options[:snapshot]
    json_path = File.directory?(snapshot) ? File.join(snapshot, JSON_FILE) : snapshot
    payload = JSON.parse(File.read(json_path))
    actors = payload.fetch('actors', [])
    existing = ActorStore.load_all
    normalized = {}
    existing.each do |actor|
      ([actor['name']] + Array(actor['aliases'])).compact.each { |value| normalized[norm(value)] = actor }
    end

    matches = actors.filter { |row| normalized.key?(norm(row['name'])) || row.fetch('aliases', []).any? { |a| normalized.key?(norm(a)) } }
    report = { 'source' => SOURCE_NAME, 'snapshot' => snapshot, 'total_records' => actors.length, 'matched_existing_actors' => matches.length, 'note' => 'Importer currently integrates BreachHQ as a reviewed matching source only (no actor writes).' }
    File.write(@options[:report_json], JSON.pretty_generate(report) + "\n") if @options[:report_json]
    puts JSON.pretty_generate(report)
    puts 'No file writes performed. BreachHQ importer currently runs in review-only mode.' if @options[:write]
  end

  def extract_actors(html)
    text = html.gsub('\\"', '"')
    rows = []
    text.scan(/"_type":"threatActor"(.*?)"type":"([^"]*)"\}/m) do |body, actor_type|
      name = body[/"name":"([^"]+)"/, 1].to_s.strip
      country = body[/"country":"([^"]*)"/, 1].to_s.strip
      slug = body[/"slug":\{"current":"([^"]*)"\}/, 1].to_s.strip
      aliases = body.scan(/"aka":\[(.*?)\],"confidence"/m).flat_map do |aka_block|
        aka_block.first.to_s.scan(/"name":"([^"]+)"/).flatten
      end.map(&:strip).reject(&:empty?).uniq
      next if name.empty?

      rows << { 'name' => name, 'aliases' => aliases, 'country' => country, 'type' => actor_type.to_s.strip, 'slug' => slug }
    end
    rows.uniq { |row| row['name'].downcase }
  end

  def read_balanced_json(text, start_idx)
    depth = 0
    in_string = false
    escaped = false
    i = start_idx
    while i < text.length
      ch = text[i]
      if in_string
        if escaped
          escaped = false
        elsif ch == '\\'
          escaped = true
        elsif ch == '"'
          in_string = false
        end
      else
        in_string = true if ch == '"'
        depth += 1 if ch == '['
        if ch == ']'
          depth -= 1
          return text[start_idx..i] if depth.zero?
        end
      end
      i += 1
    end
    raise 'Unbalanced threatActors JSON array.'
  end

  def http_get(uri, limit = 5)
    raise "Too many redirects for #{uri}" if limit <= 0

    response = Net::HTTP.get_response(uri)
    return response.body if response.is_a?(Net::HTTPSuccess)

    if response.is_a?(Net::HTTPRedirection)
      location = response['location']
      raise "Redirect without location for #{uri}" if location.to_s.empty?

      return http_get(URI.parse(location), limit - 1)
    end

    raise "HTTP #{response.code} for #{uri}"
  end

  def norm(value)
    value.to_s.downcase.gsub(/[^a-z0-9]+/, ' ').strip
  end
end

BreachHQThreatActorsImporter.new(ARGV).run
