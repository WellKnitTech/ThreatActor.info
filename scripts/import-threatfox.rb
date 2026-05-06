#!/usr/bin/env ruby
# frozen_string_literal: true

# abuse.ch ThreatFox community API importer (fetch / plan / import).
# Docs: https://threatfox.abuse.ch/api/
# Requires Auth-Key: set THREATFOX_API_KEY (sent as HTTP header Auth-Key).

require 'fileutils'
require 'json'
require 'net/http'
require 'optparse'
require 'time'
require 'uri'
require 'yaml'

require_relative 'actor_store'
require_relative 'import_utils'
require_relative 'importers/attack'
require_relative 'ioc_yaml_reader'

class ThreatFoxImporter
  DEFAULT_SNAPSHOT_ROOT = 'data/imports/threatfox'.freeze
  API_URL = 'https://threatfox-api.abuse.ch/api/v1/'.freeze

  IOC_TYPE_MAP = {
    'domain' => 'domains',
    'url' => 'urls',
    'md5_hash' => 'md5',
    'sha256_hash' => 'sha256',
    'sha1_hash' => 'sha1',
    'ip:port' => 'ips',
    'ipv4' => 'ips',
    'ipv6' => 'ips'
  }.freeze

  def initialize(argv)
    @argv = argv.dup
    @command = @argv.shift
    @options = {
      output: nil,
      snapshot: nil,
      days: 3,
      limit: nil,
      report_json: nil,
      overrides_file: File.join(DEFAULT_SNAPSHOT_ROOT, 'mapping_overrides.yml')
    }
    @overrides = { 'malware_slug_overrides' => {} }
  end

  def run
    case @command
    when 'fetch'
      parse_fetch_options
      fetch_snapshot
    when 'plan'
      parse_import_options
      run_plan_or_import(write: false)
    when 'import'
      parse_import_options
      run_plan_or_import(write: true)
    else
      puts usage
      exit 1
    end
  end

  private

  def usage
    <<~TEXT
      Usage:
        ruby scripts/import-threatfox.rb fetch [--output DIR] [--days N]
        ruby scripts/import-threatfox.rb plan --snapshot DIR [--report-json PATH] [--limit N]
        ruby scripts/import-threatfox.rb import --snapshot DIR [--report-json PATH] [--limit N]

      Environment:
        THREATFOX_API_KEY   Required for fetch (Auth-Key header).

      Notes:
        get_iocs supports days 1-7 (first_seen window). Snapshots are written under data/imports/threatfox/<date>/.
    TEXT
  end

  def parse_fetch_options
    OptionParser.new do |opts|
      opts.banner = 'Usage: ruby scripts/import-threatfox.rb fetch [options]'
      opts.on('--output DIR', 'Snapshot directory') { |v| @options[:output] = v }
      opts.on('--days N', Integer, 'Days 1-7 for get_iocs') { |v| @options[:days] = v.clamp(1, 7) }
    end.parse!(@argv)
    @options[:output] ||= File.join(DEFAULT_SNAPSHOT_ROOT, Time.now.utc.strftime('%Y-%m-%d'))
  end

  def parse_import_options
    OptionParser.new do |opts|
      opts.banner = 'Usage: ruby scripts/import-threatfox.rb plan|import --snapshot DIR [options]'
      opts.on('--snapshot DIR', 'Snapshot directory containing get_iocs.json') { |v| @options[:snapshot] = v }
      opts.on('--limit N', Integer, 'Process only first N IOC rows') { |v| @options[:limit] = v }
      opts.on('--report-json PATH', 'Write JSON report') { |v| @options[:report_json] = v }
      opts.on('--overrides PATH', 'mapping_overrides.yml path') { |v| @options[:overrides_file] = v }
    end.parse!(@argv)
    load_overrides
    abort 'Missing --snapshot' if @options[:snapshot].to_s.empty?
  end

  def load_overrides
    path = @options[:overrides_file]
    return unless path && File.file?(path)

    data = YAML.safe_load(File.read(path), permitted_classes: [], aliases: true) || {}
    h = data['malware_slug_overrides']
    @overrides['malware_slug_overrides'] = h.is_a?(Hash) ? h : {}
  end

  def fetch_snapshot
    FileUtils.mkdir_p(@options[:output])
    days = @options[:days].to_i.clamp(1, 7)
    key = ENV['THREATFOX_API_KEY'].to_s.strip
    payload = if key.empty?
                warn 'THREATFOX_API_KEY unset; writing empty snapshot (no API call). See https://auth.abuse.ch/'
                { 'query_status' => 'no_auth_key', 'data' => [] }
              else
                body = JSON.generate('query' => 'get_iocs', 'days' => days)
                http_post_json(API_URL, body, 'Auth-Key' => key)
              end

    manifest = {
      'retrieved_at' => Time.now.utc.iso8601,
      'api_url' => API_URL,
      'query' => 'get_iocs',
      'days' => days,
      'query_status' => payload['query_status'],
      'record_count' => Array(payload['data']).size
    }

    File.write(File.join(@options[:output], 'get_iocs.json'), JSON.pretty_generate(payload) + "\n")
    File.write(File.join(@options[:output], 'manifest.yml'), YAML.dump(manifest))
    puts "Wrote ThreatFox snapshot to #{@options[:output]} (#{manifest['record_count']} IOCs, status=#{manifest['query_status']})"
  end

  def http_post_json(url, body, extra_headers = {})
    uri = URI.parse(url)
    Net::HTTP.start(uri.host, uri.port, use_ssl: true) do |http|
      req = Net::HTTP::Post.new(uri)
      req['Content-Type'] = 'application/json'
      extra_headers.each { |k, v| req[k] = v }
      req.body = body
      res = http.request(req)
      raise "HTTP #{res.code} for #{url}" unless res.is_a?(Net::HTTPSuccess)

      JSON.parse(res.body)
    end
  end

  def run_plan_or_import(write:)
    path = snapshot_data_path
    payload = JSON.parse(File.read(path))
    rows = Array(payload['data'])
    rows = rows.first(@options[:limit]) if @options[:limit]
    actors = ActorStore.load_all
    alias_index = ImportUtils.build_alias_index(actors)

    plan_rows = []
    rows.each do |ioc|
      next unless ioc.is_a?(Hash)

      match = match_ioc_to_actor(ioc, actors, alias_index)
      plan_rows << { ioc_id: ioc['id'], malware: ioc['malware'], match: match }
    end

    matched = plan_rows.count { |r| r[:match] && r[:match][:position] }
    unmatched = plan_rows.size - matched

    report = {
      'mode' => write ? 'import' : 'plan',
      'snapshot' => @options[:snapshot],
      'ioc_rows' => plan_rows.size,
      'matched_actors' => matched,
      'unmatched' => unmatched
    }
    write_report_file(report)

    puts "[ThreatFox #{write ? 'IMPORT' : 'PLAN'}] IOC rows=#{plan_rows.size} matched_to_actor=#{matched} unmatched=#{unmatched}"

    return unless write

    apply_matches(rows, plan_rows, actors, path)
    puts 'ThreatFox import complete.'
  end

  def snapshot_data_path
    snap = @options[:snapshot]
    File.file?(snap) ? snap : File.join(snap, 'get_iocs.json')
  end

  def match_ioc_to_actor(ioc, actors, alias_index)
    keys = candidate_keys_for_ioc(ioc, actors)
    positions = keys.flat_map { |k| alias_index[k] || [] }.uniq
    return { position: nil, confidence: :none } if positions.empty?
    if positions.size > 1
      names = positions.map { |i| actors[i]&.dig('name') }.compact
      return { position: nil, confidence: :ambiguous, candidates: names }
    end

    { position: positions.first, confidence: :high }
  end

  def candidate_keys_for_ioc(ioc, actors)
    keys = []
    mal = ioc['malware'].to_s.strip
    slug = mal.split('.').last.to_s
    ov = @overrides['malware_slug_overrides'][mal] || @overrides['malware_slug_overrides'][slug]
    slug = ov.to_s.strip unless ov.to_s.strip.empty?

    keys << ImportUtils.canonical_key(ioc['malware_printable']) if ioc['malware_printable']
    keys << ImportUtils.canonical_key(slug) unless slug.empty?
    keys << ImportUtils.canonical_key(mal) unless mal.empty?
    Array(ioc['tags']).each { |t| keys << ImportUtils.canonical_key(t) }

    actors.each do |actor|
      Array(actor['malware']).each do |m|
        name = m.is_a?(Hash) ? m['name'] : m.to_s
        k = ImportUtils.canonical_key(name)
        keys << k if k && !k.empty?
      end
    end

    keys.compact.uniq.reject(&:empty?)
  end

  def apply_matches(rows, plan_rows, actors, snapshot_path)
    by_position = Hash.new { |h, k| h[k] = [] }
    rows.each_with_index do |ioc, idx|
      next unless ioc.is_a?(Hash)

      m = plan_rows[idx][:match]
      next unless m && m[:confidence] == :high && m[:position]

      by_position[m[:position]] << ioc
    end

    by_position.each do |position, iocs|
      actor = actors[position]
      next unless actor.is_a?(Hash)

      actor['iocs'] ||= {}
      added = 0
      unmapped_types = []
      iocs.each { |ioc| added += 1 if merge_ioc_into_actor!(actor, ioc, unmapped_types) }

      actor['provenance'] ||= {}
      tf = {
        'source_name' => 'abuse.ch ThreatFox',
        'source_dataset_url' => API_URL,
        'source_retrieved_at' => Time.now.utc.iso8601,
        'snapshot_path' => snapshot_path,
        'iocs_merged' => added
      }
      tf['unmapped_ioc_types'] = unmapped_types.uniq if unmapped_types.any?
      actor['provenance']['threatfox'] = tf

      MitreAttackGroupEnrichment.append_source!(actor, 'threatfox', dataset_url: API_URL)
      actor['iocs_count'] = count_ioc_values(actor)
    end

    puts "Writing #{by_position.size} actor files touched by ThreatFox..."
    ActorStore.save_all(actors)
  end

  def merge_ioc_into_actor!(actor, ioc, unmapped_types)
    raw = ioc['ioc'].to_s.strip
    return false if raw.empty?

    ioc_type = ioc['ioc_type'].to_s.downcase
    yaml_key = IOC_TYPE_MAP[ioc_type]
    unless yaml_key
      unmapped_types << ioc_type unless ioc_type.empty?
      return false
    end

    value = normalize_ioc_value(yaml_key, raw)
    return false if value.empty?

    actor['iocs'][yaml_key] ||= []
    return false if Array(actor['iocs'][yaml_key]).include?(value)

    actor['iocs'][yaml_key] << value
    true
  end

  def normalize_ioc_value(yaml_key, raw)
    case yaml_key
    when 'ips'
      raw.split(':').first.to_s.strip
    else
      raw
    end
  end

  def count_ioc_values(actor)
    IocYamlReader.merged_iocs_sources(actor).values.sum { |v| Array(v).size }
  end

  def write_report_file(report)
    path = @options[:report_json]
    return if path.to_s.empty?

    FileUtils.mkdir_p(File.dirname(path))
    File.write(path, JSON.pretty_generate(report))
    puts "Wrote report #{path}"
  end
end

ThreatFoxImporter.new(ARGV).run if __FILE__ == $PROGRAM_NAME
