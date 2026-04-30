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
require_relative 'import_utils'

class WizCloudThreatLandscapeImporter
  DEFAULT_SNAPSHOT_ROOT = 'data/imports/wiz-cloud-threat-landscape'.freeze
  SOURCE_NAME = 'Wiz Cloud Threat Landscape'.freeze
  STIX_URL = 'https://www.wiz.io/api/feed/cloud-threat-landscape/stix.json'.freeze
  SOURCE_ATTRIBUTION = 'Actor aliases and ATT&CK relationships imported from Wiz Cloud Threat Landscape STIX feed with provenance.'.freeze

  def initialize(argv)
    @argv = argv.dup
    @command = @argv.shift
    @options = { output: nil, snapshot: nil, write: false, report_json: nil }
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
      Usage: ruby scripts/import-wiz-cloud-threat-landscape.rb fetch|plan|import [options]

      Examples:
        ruby scripts/import-wiz-cloud-threat-landscape.rb fetch
        ruby scripts/import-wiz-cloud-threat-landscape.rb plan --snapshot data/imports/wiz-cloud-threat-landscape/2026-04-30
        ruby scripts/import-wiz-cloud-threat-landscape.rb import --snapshot data/imports/wiz-cloud-threat-landscape/2026-04-30
    TEXT
  end

  def parse_fetch_options
    OptionParser.new do |opts|
      opts.banner = 'Usage: ruby scripts/import-wiz-cloud-threat-landscape.rb fetch [options]'
      opts.on('--output DIR', 'Snapshot directory') { |value| @options[:output] = value }
    end.parse!(@argv)
    @options[:output] ||= File.join(DEFAULT_SNAPSHOT_ROOT, Time.now.utc.strftime('%Y-%m-%d'))
  end

  def parse_import_options
    OptionParser.new do |opts|
      opts.banner = 'Usage: ruby scripts/import-wiz-cloud-threat-landscape.rb plan|import --snapshot DIR [options]'
      opts.on('--snapshot DIR', 'Snapshot directory containing manifest.yml and stix.json') { |value| @options[:snapshot] = value }
      opts.on('--report-json PATH', 'Write plan report JSON') { |value| @options[:report_json] = value }
    end.parse!(@argv)
    abort 'Missing --snapshot' if @options[:snapshot].to_s.empty?
  end

  def fetch_snapshot
    FileUtils.mkdir_p(@options[:output])
    body = http_get(STIX_URL)
    stix_path = File.join(@options[:output], 'stix.json')
    File.binwrite(stix_path, body)

    manifest = {
      'source_name' => SOURCE_NAME,
      'source_url' => STIX_URL,
      'retrieved_at' => Time.now.utc.iso8601,
      'source_checksum_sha256' => Digest::SHA256.hexdigest(body),
      'includes' => {
        'actors' => 'https://threats.wiz.io/all-actors',
        'techniques' => 'https://threats.wiz.io/all-techniques',
        'tools' => 'https://threats.wiz.io/all-tools'
      }
    }
    File.write(File.join(@options[:output], 'manifest.yml'), YAML.dump(manifest))
    puts "Wrote snapshot to #{@options[:output]}"
  end

  def plan_or_import
    manifest = load_manifest
    stix = load_stix
    matched = match_updates(stix, manifest)
    report = build_report(matched, manifest)

    print_report(report)
    File.write(@options[:report_json], JSON.pretty_generate(report)) if @options[:report_json]
    apply_updates(matched, manifest) if @options[:write]
  end

  def load_manifest
    manifest_file = File.join(@options[:snapshot], 'manifest.yml')
    abort "Missing #{manifest_file}" unless File.exist?(manifest_file)

    YAML.safe_load(File.read(manifest_file), permitted_classes: [Time], aliases: true) || {}
  end

  def load_stix
    path = File.join(@options[:snapshot], 'stix.json')
    abort "Missing #{path}" unless File.exist?(path)

    JSON.parse(File.read(path))
  end

  def match_updates(stix, manifest)
    objects = Array(stix['objects'])
    intrusion_sets = objects.select { |obj| obj['type'] == 'intrusion-set' }
    relationships = objects.select { |obj| obj['type'] == 'relationship' }

    existing = ActorStore.load_all
    alias_index = ImportUtils.build_alias_index(existing)

    intrusion_sets.filter_map do |entry|
      names = [entry['name'], *Array(entry['aliases'])].compact
      actor = ImportUtils.find_actor_by_names(alias_index, names)
      next unless actor

      actor_relationships = relationships.select do |rel|
        rel['source_ref'] == entry['id'] && %w[uses attributed-to].include?(rel['relationship_type'])
      end

      {
        actor_name: actor['name'],
        data_path: actor['__data_path'],
        stix_id: entry['id'],
        stix_modified: entry['modified'],
        aliases: Array(entry['aliases']).compact.uniq,
        related_object_refs: actor_relationships.map { |rel| rel['target_ref'] }.uniq.sort
      }
    end
  end

  def build_report(matched, manifest)
    {
      timestamp: Time.now.utc.iso8601,
      source: SOURCE_NAME,
      source_url: manifest['source_url'] || STIX_URL,
      retrieved_at: manifest['retrieved_at'],
      actors_with_updates: matched.length,
      updates: matched.sort_by { |record| record[:actor_name] }
    }
  end

  def print_report(report)
    puts "\n=== #{SOURCE_NAME} Import Plan ==="
    puts "Source URL: #{report[:source_url]}"
    puts "Retrieved at: #{report[:retrieved_at]}"
    puts "Actors with updates: #{report[:actors_with_updates]}"
    report[:updates].each do |entry|
      puts "  - #{entry[:actor_name]} | aliases +#{entry[:aliases].length} | related refs #{entry[:related_object_refs].length}"
    end
    puts "\n=== Run with import to apply ===" unless @options[:write]
  end

  def apply_updates(matched, manifest)
    matched.each do |entry|
      actor = YAML.safe_load(File.read(entry[:data_path]), permitted_classes: [], aliases: true) || {}
      actor['provenance'] ||= {}
      actor['provenance']['wiz_cloud_threat_landscape'] = {
        'source_name' => SOURCE_NAME,
        'source_dataset_url' => manifest['source_url'] || STIX_URL,
        'source_retrieved_at' => manifest['retrieved_at'] || Time.now.utc.iso8601,
        'source_record_id' => entry[:stix_id],
        'source_record_modified' => entry[:stix_modified],
        'related_object_refs' => entry[:related_object_refs]
      }
      actor['aliases'] = (Array(actor['aliases']) + entry[:aliases]).uniq.sort
      actor['source_name'] ||= SOURCE_NAME
      actor['source_attribution'] ||= SOURCE_ATTRIBUTION
      File.write(entry[:data_path], YAML.dump(actor))
    end
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

WizCloudThreatLandscapeImporter.new(ARGV).run
