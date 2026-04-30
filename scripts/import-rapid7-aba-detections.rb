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

class Rapid7AbaDetectionsImporter
  DEFAULT_SNAPSHOT_ROOT = 'data/imports/rapid7-aba-detections'.freeze
  SOURCE_NAME = 'Rapid7 InsightIDR ABA Detections'.freeze
  SOURCE_URL = 'https://docs.rapid7.com/insightidr/aba-detections/'.freeze
  HTML_FILE = 'aba-detections.html'.freeze
  JSON_FILE = 'aba-detections.json'.freeze

  def initialize(argv)
    @argv = argv.dup
    @command = @argv.shift
    @options = { output: nil, snapshot: nil, report_json: nil, actor_filters: [], write: false }
  end

  def run
    case @command
    when 'fetch' then parse_fetch_options && fetch_snapshot
    when 'plan' then parse_import_options && import_snapshot
    when 'import' then parse_import_options && @options[:write] = true && import_snapshot
    else
      warn 'Usage: ruby scripts/import-rapid7-aba-detections.rb fetch|plan|import [options]'
      exit 1
    end
  end

  private

  def parse_fetch_options
    OptionParser.new { |opts| opts.on('--output DIR') { |v| @options[:output] = v } }.parse!(@argv)
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
    detections = extract_detections(html)
    json_path = File.join(@options[:output], JSON_FILE)
    File.write(json_path, JSON.pretty_generate({ 'detections' => detections }) + "\n")

    manifest = {
      'source_name' => SOURCE_NAME,
      'source_url' => SOURCE_URL,
      'retrieved_at' => Time.now.utc.iso8601,
      'record_count' => detections.length,
      'source_checksum_sha256' => Digest::SHA256.hexdigest(JSON.generate(detections))
    }
    File.write(File.join(@options[:output], 'manifest.yml'), YAML.dump(manifest))
    puts "Fetched #{detections.length} Rapid7 ABA detections into #{@options[:output]}"
  end

  def import_snapshot
    json_path = File.directory?(@options[:snapshot]) ? File.join(@options[:snapshot], JSON_FILE) : @options[:snapshot]
    payload = JSON.parse(File.read(json_path))
    detections = payload.fetch('detections', [])

    existing = ActorStore.load_all
    lookup = build_lookup(existing)
    candidates = build_candidates(detections, lookup)

    if @options[:actor_filters].any?
      wanted = @options[:actor_filters].map { |v| normalize(v) }.to_set
      candidates.select! { |c| wanted.include?(normalize(c['actor_name'])) }
    end

    report = {
      'source' => SOURCE_NAME,
      'snapshot' => @options[:snapshot],
      'total_detections' => detections.length,
      'matched_existing_actors' => candidates.length,
      'actors_with_reference_updates' => candidates.count { |c| c.dig('changes', 'new_references')&.any? },
      'updated_actor_names' => candidates.select { |c| c.dig('changes', 'new_references')&.any? }.map { |c| c['actor_name'] }.uniq.sort
    }
    File.write(@options[:report_json], JSON.pretty_generate(report) + "\n") if @options[:report_json]
    puts JSON.pretty_generate(report)

    return unless @options[:write]

    apply_candidates(candidates, existing)
    ActorStore.save_all(existing)
  end

  def extract_detections(html)
    records = []
    html.scan(/<h2[^>]*id=["']([^"']+)["'][^>]*>(.*?)<\/h2>/im) do |id, title_html|
      title = clean(title_html)
      next if title.empty?
      snippet = html[Regexp.last_match.end(0), 2000].to_s
      description = clean(snippet[/<p[^>]*>(.*?)<\/p>/im, 1])
      records << {
        'id' => id,
        'title' => title,
        'description' => description,
        'url' => "#{SOURCE_URL}##{id}"
      }
    end
    records.uniq { |r| r['id'] }
  end

  def build_lookup(actors)
    actors.each_with_object({}) do |actor, memo|
      ([actor['name']] + Array(actor['aliases'])).compact.each { |name| memo[normalize(name)] = actor }
    end
  end

  def build_candidates(detections, lookup)
    detections.flat_map do |det|
      text = [det['title'], det['description']].join(' ')
      lookup.each_with_object([]) do |(key, actor), memo|
        next if key.empty?
        next unless text.downcase.include?(key)

        memo << candidate_for(actor, det)
      end
    end.group_by { |c| normalize(c['actor_name']) }.values.map { |arr| merge_actor_candidates(arr) }
  end

  def candidate_for(actor, detection)
    refs = Array(actor['references'])
    link = { 'title' => "Rapid7 ABA: #{detection['title']}", 'url' => detection['url'] }
    new_refs = refs.any? { |r| r.is_a?(Hash) && r['url'] == link['url'] } ? [] : [link]
    {
      'actor_name' => actor['name'],
      'changes' => { 'new_references' => new_refs },
      'provenance' => {
        'source_name' => SOURCE_NAME,
        'source_url' => SOURCE_URL,
        'detection_ids' => [detection['id']]
      }
    }
  end

  def merge_actor_candidates(candidates)
    first = Marshal.load(Marshal.dump(candidates.first))
    refs = candidates.flat_map { |c| c.dig('changes', 'new_references') || [] }.uniq { |r| r['url'] }
    ids = candidates.flat_map { |c| c.dig('provenance', 'detection_ids') || [] }.uniq.sort
    first['changes']['new_references'] = refs
    first['provenance']['detection_ids'] = ids
    first
  end

  def apply_candidates(candidates, existing)
    by_name = existing.each_with_object({}) { |actor, memo| memo[normalize(actor['name'])] = actor }
    candidates.each do |candidate|
      actor = by_name[normalize(candidate['actor_name'])]
      next unless actor

      actor['references'] ||= []
      actor['references'] = (Array(actor['references']) + Array(candidate.dig('changes', 'new_references'))).uniq { |r| r.is_a?(Hash) ? r['url'] : r }
      actor['provenance'] ||= {}
      actor['provenance']['rapid7_aba_detections'] = candidate['provenance']
    end
  end

  def http_get(uri)
    response = Net::HTTP.get_response(uri)
    raise "HTTP #{response.code} for #{uri}" unless response.is_a?(Net::HTTPSuccess)

    response.body
  end

  def clean(value)
    value.to_s.gsub(/<[^>]+>/, ' ').gsub(/\s+/, ' ').strip
  end

  def normalize(value)
    value.to_s.downcase.gsub(/[^a-z0-9]+/, ' ').strip
  end
end

Rapid7AbaDetectionsImporter.new(ARGV).run
