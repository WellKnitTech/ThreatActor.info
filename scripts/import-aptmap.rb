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

class AptmapImporter
  DEFAULT_SNAPSHOT_ROOT = 'data/imports/aptmap'.freeze
  APT_FILE = 'apt.json'.freeze
  REL_FILE = 'apt_rel.json'.freeze
  SOURCE_URLS = {
    APT_FILE => [
      'https://raw.githubusercontent.com/andreacristaldi/APTmap/master/apt.json',
      'https://raw.githubusercontent.com/andreacristaldi/APTmap/main/apt.json'
    ],
    REL_FILE => [
      'https://raw.githubusercontent.com/andreacristaldi/APTmap/master/apt_rel.json',
      'https://raw.githubusercontent.com/andreacristaldi/APTmap/main/apt_rel.json'
    ]
  }.freeze

  def initialize(argv)
    @argv = argv.dup
    @command = @argv.shift
    @options = { output: nil, snapshot: nil, report_json: nil, limit: nil, write: false }
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
    "Usage: ruby scripts/import-aptmap.rb fetch|plan|import [options]"
  end

  def parse_fetch_options
    OptionParser.new do |opts|
      opts.on('--output DIR', 'Snapshot output directory') { |value| @options[:output] = value }
    end.parse!(@argv)
    @options[:output] ||= File.join(DEFAULT_SNAPSHOT_ROOT, Time.now.utc.strftime('%Y-%m-%d'))
  end

  def parse_import_options
    OptionParser.new do |opts|
      opts.on('--snapshot PATH', 'Snapshot directory') { |value| @options[:snapshot] = value }
      opts.on('--report-json PATH', 'Write report json') { |value| @options[:report_json] = value }
      opts.on('--limit N', Integer, 'Limit records') { |value| @options[:limit] = value }
    end.parse!(@argv)
    return if @options[:snapshot]

    warn 'Missing required --snapshot PATH'
    exit 1
  end

  def fetch_snapshot
    FileUtils.mkdir_p(@options[:output])
    checksums = {}

    [APT_FILE, REL_FILE].each do |file_name|
      body = fetch_with_fallback(SOURCE_URLS.fetch(file_name))
      out = File.join(@options[:output], file_name)
      File.binwrite(out, body)
      checksums[file_name] = Digest::SHA256.hexdigest(body)
    end

    apt_rows = JSON.parse(File.read(File.join(@options[:output], APT_FILE)))
    manifest = {
      'source_name' => 'APTmap',
      'source_url' => 'https://github.com/andreacristaldi/APTmap',
      'retrieved_at' => Time.now.utc.iso8601,
      'record_count' => apt_rows.is_a?(Array) ? apt_rows.length : 0,
      'checksums_sha256' => checksums
    }
    File.write(File.join(@options[:output], 'manifest.yml'), YAML.dump(manifest))
    puts "Fetched APTmap snapshot into #{@options[:output]}"
  end

  def fetch_with_fallback(urls)
    errors = []
    urls.each do |url|
      uri = URI.parse(url)
      response = Net::HTTP.get_response(uri)
      return response.body if response.is_a?(Net::HTTPSuccess)

      errors << "#{url} (HTTP #{response.code})"
    rescue StandardError => e
      errors << "#{url} (#{e.class}: #{e.message})"
    end
    raise "Unable to fetch source file. Tried: #{errors.join(', ')}"
  end

  def plan_or_import
    apt_path = File.join(@options[:snapshot], APT_FILE)
    rel_path = File.join(@options[:snapshot], REL_FILE)
    apt_rows = JSON.parse(File.read(apt_path))
    rel_rows = File.exist?(rel_path) ? JSON.parse(File.read(rel_path)) : []

    apt_rows = apt_rows.first(@options[:limit]) if @options[:limit]
    actors = ActorStore.load_all
    by_name = {}
    actors.each do |actor|
      by_name[actor['name'].to_s.downcase] = actor
      Array(actor['aliases']).each { |al| by_name[al.to_s.downcase] ||= actor }
    end

    candidates = apt_rows.filter_map do |row|
      normalized = normalize_row(row)
      next unless normalized

      existing = by_name[normalized[:name].downcase]
      {
        'name' => normalized[:name],
        'aliases' => normalized[:aliases],
        'matched_actor' => existing ? existing['name'] : nil,
        'action' => existing ? 'match' : 'new_candidate'
      }
    end

    report = {
      'source' => 'aptmap',
      'snapshot' => @options[:snapshot],
      'apt_records' => apt_rows.length,
      'relationship_records' => rel_rows.is_a?(Array) ? rel_rows.length : 0,
      'matched' => candidates.count { |c| c['action'] == 'match' },
      'new_candidates' => candidates.count { |c| c['action'] == 'new_candidate' },
      'candidates' => candidates
    }

    File.write(@options[:report_json], JSON.pretty_generate(report) + "\n") if @options[:report_json]
    puts "APTmap plan: #{report['matched']} matched, #{report['new_candidates']} new candidates"
    puts 'Import mode currently produces planning output only; no actor files are modified yet.' if @options[:write]
  end

  def normalize_row(row)
    return nil unless row.is_a?(Hash)

    name = first_present(row, %w[name Name actor actor_name group])
    return nil if name.to_s.strip.empty?

    aliases = first_present(row, %w[aliases alias aka AKA])
    aliases = aliases.split(',').map(&:strip) if aliases.is_a?(String)
    aliases = Array(aliases).map(&:to_s).map(&:strip).reject(&:empty?).uniq

    { name: name.strip, aliases: aliases }
  end

  def first_present(hash, keys)
    keys.each do |key|
      value = hash[key]
      return value unless value.nil?
    end
    nil
  end
end

AptmapImporter.new(ARGV).run
