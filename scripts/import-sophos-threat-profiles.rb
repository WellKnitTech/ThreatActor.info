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

class SophosThreatProfilesImporter
  DEFAULT_SNAPSHOT_ROOT = 'data/imports/sophos-threat-profiles'.freeze
  SOURCE_NAME = 'Sophos Threat Profiles'.freeze
  SOURCE_URL = 'https://www.sophos.com/en-us/threat-profiles?page=1&pageSize=10'.freeze
  HTML_FILE = 'threat-profiles.html'.freeze
  JSON_FILE = 'threat-profiles.json'.freeze

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
      warn 'Usage: ruby scripts/import-sophos-threat-profiles.rb fetch|plan|import [options]'
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
    File.binwrite(File.join(@options[:output], HTML_FILE), html)

    dataset = fetch_download_all_dataset(html)
    profiles = dataset || extract_profiles_from_html(html)

    File.write(File.join(@options[:output], JSON_FILE), JSON.pretty_generate({ 'profiles' => profiles }) + "\n")
    manifest = {
      'source_name' => SOURCE_NAME,
      'source_url' => SOURCE_URL,
      'retrieved_at' => Time.now.utc.iso8601,
      'record_count' => profiles.length,
      'used_download_all_data' => !dataset.nil?
    }
    File.write(File.join(@options[:output], 'manifest.yml'), YAML.dump(manifest))
    puts "Fetched #{profiles.length} Sophos threat profile rows into #{@options[:output]}"
  end

  def fetch_download_all_dataset(html)
    match = html.match(/href=["']([^"']*download[^"']*(?:json|csv)[^"']*)["']/i)
    return nil unless match

    href = match[1]
    url = href.start_with?('http') ? href : URI.join('https://www.sophos.com', href).to_s
    body = http_get(URI.parse(url))

    if url.downcase.end_with?('.json') || body.lstrip.start_with?('{', '[')
      payload = JSON.parse(body)
      rows = payload.is_a?(Array) ? payload : payload['profiles'] || payload['data'] || payload.values.find { |v| v.is_a?(Array) } || []
      normalize_profiles(rows)
    elsif url.downcase.end_with?('.csv')
      parse_csv_rows(body)
    end
  rescue StandardError
    nil
  end

  def extract_profiles_from_html(html)
    rows = []
    html.scan(%r{<a[^>]+href=["']([^"']*/threat-profiles/[^"']+)["'][^>]*>(.*?)</a>}im) do |href, title_html|
      title = clean(title_html)
      next if title.empty?
      rows << { 'name' => title, 'aliases' => [], 'description' => '', 'url' => href.start_with?('http') ? href : "https://www.sophos.com#{href}" }
    end
    rows.uniq { |r| normalize(r['name']) }
  end

  def parse_csv_rows(csv_text)
    lines = csv_text.split("\n").map(&:strip).reject(&:empty?)
    header = lines.shift.to_s.split(',').map(&:strip)
    name_i = header.index { |h| h.match?(/name|profile/i) } || 0
    desc_i = header.index { |h| h.match?(/description|summary/i) }
    url_i = header.index { |h| h.match?(/url|link/i) }
    lines.map do |line|
      cols = line.split(',').map { |c| c.to_s.strip.gsub(/^"|"$/, '') }
      {
        'name' => cols[name_i].to_s,
        'aliases' => [],
        'description' => desc_i ? cols[desc_i].to_s : '',
        'url' => url_i ? cols[url_i].to_s : SOURCE_URL
      }
    end.reject { |r| r['name'].to_s.empty? }
  end

  def normalize_profiles(rows)
    Array(rows).filter_map do |row|
      next unless row.is_a?(Hash)
      name = clean(row['name'] || row['title'] || row['profile'])
      next if name.empty?
      aliases = Array(row['aliases'] || row['aka']).map { |a| clean(a) }.reject(&:empty?).uniq
      description = clean(row['description'] || row['summary'])
      url = row['url'] || row['link'] || SOURCE_URL
      { 'name' => name, 'aliases' => aliases, 'description' => description, 'url' => url }
    end
  end

  def import_snapshot
    json_path = File.directory?(@options[:snapshot]) ? File.join(@options[:snapshot], JSON_FILE) : @options[:snapshot]
    profiles = JSON.parse(File.read(json_path)).fetch('profiles', [])
    existing = ActorStore.load_all
    lookup = build_lookup(existing)

    candidates = profiles.filter_map do |row|
      actor = lookup[normalize(row['name'])] || Array(row['aliases']).map { |a| lookup[normalize(a)] }.compact.first
      next unless actor
      next if @options[:actor_filters].any? { |f| normalize(actor['name']) != normalize(f) }

      build_candidate(actor, row)
    end

    report = {
      'source' => SOURCE_NAME,
      'snapshot' => @options[:snapshot],
      'total_records' => profiles.length,
      'matched_existing_actors' => candidates.length,
      'actors_with_reference_updates' => candidates.count { |c| c.dig('changes', 'new_references')&.any? },
      'actors_with_alias_updates' => candidates.count { |c| c.dig('changes', 'new_aliases')&.any? },
      'actors_with_description_updates' => candidates.count { |c| !c.dig('changes', 'description_update').to_s.empty? }
    }
    File.write(@options[:report_json], JSON.pretty_generate(report) + "\n") if @options[:report_json]
    puts JSON.pretty_generate(report)

    return unless @options[:write]

    apply_candidates(existing, candidates)
    ActorStore.save_all(existing)
  end

  def build_lookup(existing)
    existing.each_with_object({}) do |actor, memo|
      ([actor['name']] + Array(actor['aliases'])).compact.each { |v| memo[normalize(v)] = actor }
    end
  end

  def build_candidate(actor, row)
    existing_aliases = Array(actor['aliases']).map(&:to_s)
    incoming_aliases = Array(row['aliases']).map(&:to_s)
    new_aliases = incoming_aliases.reject { |value| existing_aliases.any? { |existing| normalize(existing) == normalize(value) } || normalize(actor['name']) == normalize(value) }
    description_update = merge_description_with_source(actor['description'], row['description'], row['url'])

    link = { 'title' => "Sophos Threat Profile: #{row['name']}", 'url' => row['url'].to_s.empty? ? SOURCE_URL : row['url'] }
    existing_refs = Array(actor['references'])
    new_refs = existing_refs.any? { |ref| ref.is_a?(Hash) && ref['url'] == link['url'] } ? [] : [link]

    {
      'actor_name' => actor['name'],
      'changes' => { 'new_references' => new_refs, 'new_aliases' => new_aliases, 'description_update' => description_update },
      'provenance' => {
        'source_name' => SOURCE_NAME,
        'source_url' => SOURCE_URL,
        'source_profile_url' => link['url']
      }
    }
  end

  def apply_candidates(existing, candidates)
    by_name = existing.each_with_object({}) { |actor, memo| memo[normalize(actor['name'])] = actor }
    candidates.each do |candidate|
      actor = by_name[normalize(candidate['actor_name'])]
      next unless actor
      actor['aliases'] ||= []
      actor['aliases'] = (Array(actor['aliases']) + Array(candidate.dig('changes', 'new_aliases'))).uniq
      actor['references'] ||= []
      actor['references'] = (Array(actor['references']) + Array(candidate.dig('changes', 'new_references'))).uniq { |r| r.is_a?(Hash) ? r['url'] : r }
      description_update = candidate.dig('changes', 'description_update').to_s.strip
      actor['description'] = description_update unless description_update.empty?
      actor['provenance'] ||= {}
      actor['provenance']['sophos_threat_profiles'] = candidate['provenance']
    end
  end

  def merge_description_with_source(current_description, incoming_description, source_url)
    incoming = clean(incoming_description)
    return nil if incoming.empty?

    current = clean(current_description)
    return incoming if current.empty?

    heading = '### Source: Sophos Threat Profiles'
    return nil if current.include?(heading)

    [current, heading, incoming, source_url.to_s.empty? ? SOURCE_URL : source_url.to_s].join("\n\n")
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

SophosThreatProfilesImporter.new(ARGV).run
