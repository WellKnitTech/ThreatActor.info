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

class DragosThreatGroupsImporter
  DEFAULT_SNAPSHOT_ROOT = 'data/imports/dragos-threat-groups'.freeze
  SOURCE_NAME = 'Dragos Threat Groups'.freeze
  SOURCE_URL = 'https://www.dragos.com/threat-groups'.freeze
  SOURCE_ATTRIBUTION = 'Aliases were reviewed from the Dragos threat-groups catalog and preserved with source provenance.'.freeze

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
      Usage: ruby scripts/import-dragos-threat-groups.rb fetch|plan|import [options]
    TEXT
  end

  def parse_fetch_options
    OptionParser.new do |opts|
      opts.banner = 'Usage: ruby scripts/import-dragos-threat-groups.rb fetch [options]'
      opts.on('--output DIR', 'Snapshot directory') { |value| @options[:output] = value }
    end.parse!(@argv)
    @options[:output] ||= File.join(DEFAULT_SNAPSHOT_ROOT, Time.now.utc.strftime('%Y-%m-%d'))
  end

  def parse_import_options
    OptionParser.new do |opts|
      opts.banner = 'Usage: ruby scripts/import-dragos-threat-groups.rb plan|import --snapshot DIR [options]'
      opts.on('--snapshot DIR', 'Snapshot directory') { |value| @options[:snapshot] = value }
      opts.on('--report-json PATH', 'Write JSON report') { |value| @options[:report_json] = value }
    end.parse!(@argv)
    abort 'Missing --snapshot' if @options[:snapshot].to_s.empty?
  end

  def fetch_snapshot
    FileUtils.mkdir_p(@options[:output])

    root_html = http_get(SOURCE_URL)
    root_doc = Nokogiri::HTML(root_html)
    links = extract_profile_links(root_doc)

    details_dir = File.join(@options[:output], 'pages')
    FileUtils.mkdir_p(details_dir)

    pages = links.map do |url|
      html = http_get(url)
      slug = URI.parse(url).path.split('/').reject(&:empty?).last
      file_name = "#{slug}.html"
      File.write(File.join(details_dir, file_name), html)
      {
        'url' => url,
        'file' => "pages/#{file_name}",
        'sha256' => Digest::SHA256.hexdigest(html)
      }
    end

    actors = parse_actors(root_doc, pages)

    File.write(File.join(@options[:output], 'index.html'), root_html)
    File.write(File.join(@options[:output], 'actors.json'), JSON.pretty_generate(actors))
    manifest = {
      'source_name' => SOURCE_NAME,
      'source_url' => SOURCE_URL,
      'retrieved_at' => Time.now.utc.iso8601,
      'source_checksum_sha256' => Digest::SHA256.hexdigest(root_html),
      'detail_page_count' => pages.length,
      'record_count' => actors.length,
      'detail_pages' => pages
    }
    File.write(File.join(@options[:output], 'manifest.yml'), YAML.dump(manifest))
    puts "Wrote snapshot to #{@options[:output]} (#{actors.length} parsed records, #{pages.length} detail pages)"
  end

  def extract_profile_links(doc)
    hrefs = doc.css('a[href]').map { |a| a['href'] }.compact
    hrefs.filter_map do |href|
      next unless href.include?('/threat-groups/')

      absolute = URI.join(SOURCE_URL + '/', href).to_s
      uri = URI.parse(absolute)
      next unless uri.host == URI.parse(SOURCE_URL).host
      next if uri.path == '/threat-groups' || uri.path == '/threat-groups/'

      absolute
    rescue URI::InvalidURIError
      nil
    end.uniq.sort
  end

  def parse_actors(root_doc, pages)
    rows = []
    root_doc.css('a[href]').each do |link|
      href = link['href'].to_s
      text = normalize_name(link.text)
      next if text.empty? || href.empty?
      next unless href.include?('/threat-groups/')

      rows << { 'name' => text, 'source_url' => URI.join(SOURCE_URL + '/', href).to_s }
    end

    pages.each do |page|
      html = File.read(File.join(@options[:output], page['file']))
      doc = Nokogiri::HTML(html)
      title = normalize_name(doc.at_css('h1')&.text)
      next if title.empty?

      rows << { 'name' => title, 'source_url' => page['url'] }
    end

    rows.group_by { |row| row['name'].downcase }.map do |_, grouped|
      primary = grouped.first
      {
        'name' => primary['name'],
        'aliases' => [],
        'source_urls' => grouped.map { |row| row['source_url'] }.uniq.sort
      }
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
      actor = ImportUtils.find_actor_by_names(alias_index, [entry['name']])
      next unless actor

      {
        actor_name: actor['name'],
        data_path: actor['__data_path'],
        source_name: entry['name'],
        aliases: Array(entry['aliases']),
        source_urls: Array(entry['source_urls'])
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
      actor['provenance']['dragos_threat_groups'] = {
        'source_name' => SOURCE_NAME,
        'source_dataset_url' => SOURCE_URL,
        'source_retrieved_at' => manifest['retrieved_at'] || Time.now.utc.iso8601,
        'source_record_id' => update[:source_name],
        'source_urls' => update[:source_urls]
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

DragosThreatGroupsImporter.new(ARGV).run
