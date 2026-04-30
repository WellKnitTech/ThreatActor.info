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
require 'cgi'
require_relative 'actor_store'

class GoogleCloudAptGroupsImporter
  DEFAULT_SNAPSHOT_ROOT = 'data/imports/google-cloud-apt-groups'.freeze
  SOURCE_NAME = 'Google Cloud APT Groups'.freeze
  SOURCE_URL = 'https://cloud.google.com/security/resources/insights/apt-groups'.freeze
  HTML_FILE = 'apt-groups.html'.freeze
  JSON_FILE = 'apt-groups.json'.freeze

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
      warn 'Usage: ruby scripts/import-google-cloud-apt-groups.rb fetch|plan|import [options]'
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
    actors = extract_actors(html)
    json_path = File.join(@options[:output], JSON_FILE)
    File.write(json_path, JSON.pretty_generate({ 'actors' => actors }) + "\n")

    manifest = {
      'source_name' => SOURCE_NAME,
      'source_url' => SOURCE_URL,
      'retrieved_at' => Time.now.utc.iso8601,
      'record_count' => actors.length,
      'license_status' => 'Use as a secondary naming crosswalk with preserved source attribution.',
      'checksums_sha256' => {
        HTML_FILE => Digest::SHA256.file(html_path).hexdigest,
        JSON_FILE => Digest::SHA256.file(json_path).hexdigest
      }
    }
    File.write(File.join(@options[:output], 'manifest.yml'), YAML.dump(manifest))
    puts "Fetched #{actors.length} Google Cloud APT group rows into #{@options[:output]}"
  end

  def import_snapshot
    json_path = File.directory?(@options[:snapshot]) ? File.join(@options[:snapshot], JSON_FILE) : @options[:snapshot]
    manifest_path = File.join(File.dirname(json_path), 'manifest.yml')
    payload = JSON.parse(File.read(json_path))
    manifest = File.exist?(manifest_path) ? YAML.safe_load(File.read(manifest_path), permitted_classes: [Time], aliases: true) : {}
    actors = payload.fetch('actors', [])
    existing = ActorStore.load_all
    lookup = build_lookup(existing)

    candidates = actors.filter_map do |row|
      actor = lookup[norm(row['name'])]
      next unless actor
      next if @options[:actor_filters].any? { |f| norm(actor['name']) != norm(f) && norm(row['name']) != norm(f) }

      build_candidate(actor, row, manifest)
    end

    report = {
      'source' => SOURCE_NAME,
      'snapshot' => @options[:snapshot],
      'total_records' => actors.length,
      'matched_existing_actors' => candidates.length,
      'actors_with_description_updates' => candidates.count { |c| !c.dig('changes', 'description_update').to_s.empty? },
      'updated_actor_names' => candidates.select { |c| c.dig('changes', 'new_aliases')&.any? }.map { |c| c['actor_name'] }.uniq.sort
    }
    File.write(@options[:report_json], JSON.pretty_generate(report) + "\n") if @options[:report_json]
    puts JSON.pretty_generate(report)
    return unless @options[:write]

    apply_candidates(candidates, existing)
    ActorStore.save_all(existing)
  end

  def build_lookup(existing)
    existing.each_with_object({}) do |actor, memo|
      ([actor['name']] + Array(actor['aliases'])).compact.each { |v| memo[norm(v)] = actor }
    end
  end

  def build_candidate(actor, row, manifest)
    existing_aliases = Array(actor['aliases']).map(&:to_s)
    incoming_aliases = Array(row['aliases']).map(&:to_s)
    new_aliases = incoming_aliases.reject { |value| existing_aliases.any? { |existing| norm(existing) == norm(value) } || norm(actor['name']) == norm(value) }

    current_description = actor['description'].to_s.strip
    incoming_description = row['description'].to_s.strip
    description_update = merged_description(current_description, incoming_description, row['url'])

    {
      'actor_name' => actor['name'],
      'changes' => { 'new_aliases' => new_aliases, 'description_update' => description_update },
      'provenance' => {
        'source_name' => SOURCE_NAME,
        'source_url' => SOURCE_URL,
        'retrieved_at' => manifest['retrieved_at'],
        'source_dataset_url' => row['url'].to_s.empty? ? SOURCE_URL : row['url']
      }
    }
  end

  def apply_candidates(candidates, existing)
    by_name = existing.each_with_object({}) { |actor, memo| memo[norm(actor['name'])] = actor }
    candidates.each do |candidate|
      actor = by_name[norm(candidate['actor_name'])]
      next unless actor

      actor['aliases'] ||= []
      actor['aliases'] = (Array(actor['aliases']) + Array(candidate.dig('changes', 'new_aliases'))).uniq
      description_update = candidate.dig('changes', 'description_update').to_s.strip
      actor['description'] = description_update unless description_update.empty?
      actor['provenance'] ||= {}
      actor['provenance']['google_cloud_apt_groups'] = candidate['provenance']
    end
  end

  def extract_actors(html)
    actors = []
    html.scan(%r{<a[^>]+href=["']([^"']+)["'][^>]*>(.*?)</a>}im) do |href, label|
      next unless apt_group_href?(href)

      name = strip_tags(label).strip
      next if name.empty? || name.casecmp('APT groups and threat actors').zero?
      description = extract_local_description(html, Regexp.last_match.end(0))

      actors << {
        'name' => name,
        'aliases' => [],
        'description' => description,
        'url' => href.start_with?('http') ? href : "https://cloud.google.com#{href}"
      }
    end
    actors.uniq { |row| norm(row['name']) }
  end

  def extract_local_description(html, start_index)
    window = html[start_index, 600].to_s
    text = strip_tags(window).strip
    return '' if text.empty?

    sentence = text.split(/(?<=[.!?])\s+/).first.to_s.strip
    sentence.length > 30 ? sentence : ''
  end

  def strip_tags(value)
    CGI.unescapeHTML(value.to_s.gsub(/<[^>]+>/, ' ')).gsub(/\s+/, ' ')
  end

  def merged_description(current_description, incoming_description, source_url)
    return nil if incoming_description.empty?
    return incoming_description if current_description.empty?
    return nil if current_description.include?('### Source: Google Cloud APT Groups')

    incoming_sentence = incoming_description.gsub(/\s+/, ' ').strip
    section = [
      '### Source: Google Cloud APT Groups',
      incoming_sentence,
      source_url.to_s.empty? ? SOURCE_URL : source_url.to_s
    ].join("\n")

    [current_description, section].join("\n\n")
  end

  def apt_group_href?(href)
    normalized = CGI.unescapeHTML(href.to_s)
    return true if normalized.start_with?('/security/resources/insights/apt-')

    uri = URI.parse(normalized)
    uri.host == 'cloud.google.com' && uri.path.start_with?('/security/resources/insights/apt-')
  rescue URI::InvalidURIError
    false
  end

  def http_get(uri, limit = 5)
    raise "Too many redirects for #{uri}" if limit <= 0

    response = Net::HTTP.get_response(uri)
    return response.body if response.is_a?(Net::HTTPSuccess)
    return http_get(URI.parse(response['location']), limit - 1) if response.is_a?(Net::HTTPRedirection) && !response['location'].to_s.empty?

    raise "HTTP #{response.code} for #{uri}"
  end

  def norm(value)
    value.to_s.downcase.gsub(/[^a-z0-9]+/, ' ').strip
  end
end

GoogleCloudAptGroupsImporter.new(ARGV).run
