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
    @options = { output: nil, snapshot: nil, report_json: nil, write: false, actor_filters: [] }
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
      opts.on('--actor NAME') { |v| @options[:actor_filters] << v }
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
    manifest_path = File.join(File.dirname(json_path), 'manifest.yml')
    payload = JSON.parse(File.read(json_path))
    manifest = File.exist?(manifest_path) ? YAML.safe_load(File.read(manifest_path), permitted_classes: [Time], aliases: true) : {}
    actors = payload.fetch('actors', [])
    existing = ActorStore.load_all
    lookup = build_lookup(existing)

    candidates = actors.filter_map do |row|
      actor = find_existing_actor(row, lookup)
      next unless actor
      next if @options[:actor_filters].any? { |f| norm(actor['name']) != norm(f) && norm(row['name']) != norm(f) }

      build_candidate(actor, row, manifest)
    end

    report = build_report(snapshot, actors.length, candidates)
    File.write(@options[:report_json], JSON.pretty_generate(report) + "
") if @options[:report_json]
    puts JSON.pretty_generate(report)

    return unless @options[:write]

    apply_candidates(candidates, existing)
    ActorStore.save_all(existing)
    puts "Applied BreachHQ enrichment to #{candidates.count { |c| c['changes'].any? }} actors"
  end

  def build_lookup(existing)
    lookup = {}
    existing.each do |actor|
      ([actor['name']] + Array(actor['aliases'])).compact.each { |value| lookup[norm(value)] = actor }
    end
    lookup
  end

  def find_existing_actor(row, lookup)
    lookup[norm(row['name'])] || row.fetch('aliases', []).map { |a| lookup[norm(a)] }.compact.first
  end

  def build_candidate(actor, row, manifest)
    existing_aliases = Array(actor['aliases']).map(&:to_s)
    incoming_aliases = row.fetch('aliases', []).map(&:to_s)
    new_aliases = incoming_aliases.reject { |value| existing_aliases.any? { |existing| norm(existing) == norm(value) } || norm(actor['name']) == norm(value) }

    existing_country = actor['country'].to_s.strip
    incoming_country = row['country'].to_s.strip
    country_update = existing_country.empty? && !incoming_country.empty? && incoming_country.downcase != 'unknown' ? incoming_country : nil

    {
      'actor_name' => actor['name'],
      'source_name' => row['name'],
      'changes' => {
        'new_aliases' => new_aliases,
        'country_update' => country_update
      },
      'provenance' => {
        'source_name' => SOURCE_NAME,
        'source_url' => SOURCE_URL,
        'retrieved_at' => manifest['retrieved_at'],
        'dataset_slug' => row['slug'],
        'actor_type' => row['type'],
        'country' => incoming_country,
        'source_dataset_url' => row['slug'].to_s.empty? ? SOURCE_URL : "#{SOURCE_URL}/#{row['slug']}"
      }
    }
  end

  def build_report(snapshot, total_records, candidates)
    {
      'source' => SOURCE_NAME,
      'snapshot' => snapshot,
      'total_records' => total_records,
      'matched_existing_actors' => candidates.length,
      'actors_with_alias_updates' => candidates.count { |c| c.dig('changes', 'new_aliases')&.any? },
      'actors_with_country_updates' => candidates.count { |c| !c.dig('changes', 'country_update').to_s.empty? },
      'updated_actor_names' => candidates.select { |c| c['changes'].any? { |_k, v| v.respond_to?(:any?) ? v.any? : !v.to_s.empty? } }.map { |c| c['actor_name'] }.uniq.sort
    }
  end

  def apply_candidates(candidates, existing)
    by_name = existing.each_with_object({}) { |actor, memo| memo[norm(actor['name'])] = actor }
    candidates.each do |candidate|
      next unless candidate['changes'].any? { |_k, v| v.respond_to?(:any?) ? v.any? : !v.to_s.empty? }

      actor = by_name[norm(candidate['actor_name'])]
      next unless actor

      actor['aliases'] ||= []
      actor['aliases'] = (Array(actor['aliases']) + candidate.dig('changes', 'new_aliases')).uniq
      country_update = candidate.dig('changes', 'country_update')
      actor['country'] = country_update unless country_update.to_s.empty?
      actor['provenance'] ||= {}
      actor['provenance']['breach_hq'] = candidate['provenance']
    end
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
