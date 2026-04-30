#!/usr/bin/env ruby
# frozen_string_literal: true

require 'digest'
require 'fileutils'
require 'json'
require 'net/http'
require 'optparse'
require 'time'
require 'yaml'
require_relative 'actor_store'

class RedDrip7AptDigitalWeaponImporter
  DEFAULT_API_ROOT = 'https://api.github.com/repos/RedDrip7/APT_Digital_Weapon'.freeze
  DEFAULT_SNAPSHOT_ROOT = 'data/imports/reddrip7-apt-digital-weapon'.freeze
  SOURCE_DATASET_URL = 'https://github.com/RedDrip7/APT_Digital_Weapon'.freeze
  SOURCE_ATTRIBUTION = 'Indicators of compromise were reviewed from RedDrip7/APT_Digital_Weapon and are treated as secondary, community-curated leads requiring independent verification before operational use.'.freeze

  def initialize(argv)
    @argv = argv.dup
    @command = @argv.shift
    @options = { api_root: DEFAULT_API_ROOT, output: nil, snapshot: nil, report_json: nil, write: false }
  end

  def run
    case @command
    when 'fetch'
      parse_fetch_options
      fetch
    when 'plan'
      parse_plan_options
      process_snapshot(false)
    when 'import'
      parse_plan_options
      process_snapshot(true)
    else
      warn usage
      exit 1
    end
  end

  private

  def usage
    "Usage: ruby scripts/import-reddrip7-apt-digital-weapon.rb fetch|plan|import [options]"
  end

  def parse_fetch_options
    OptionParser.new do |opts|
      opts.on('--api-root URL') { |v| @options[:api_root] = v }
      opts.on('--output DIR') { |v| @options[:output] = v }
    end.parse!(@argv)
    @options[:output] ||= File.join(DEFAULT_SNAPSHOT_ROOT, Time.now.utc.strftime('%Y-%m-%d'))
  end

  def parse_plan_options
    OptionParser.new do |opts|
      opts.on('--snapshot PATH') { |v| @options[:snapshot] = v }
      opts.on('--report-json PATH') { |v| @options[:report_json] = v }
    end.parse!(@argv)
    abort 'A snapshot path is required.' unless @options[:snapshot]
  end

  def fetch
    FileUtils.mkdir_p(@options[:output])
    items = http_get_json("#{@options[:api_root]}/contents/")
    directories = Array(items).select { |row| row['type'] == 'dir' }
    records = directories.map do |row|
      folder = row['name']
      {
        'folder' => folder,
        'folder_key' => normalize(folder),
        'actor_readme_url' => "https://raw.githubusercontent.com/RedDrip7/APT_Digital_Weapon/master/#{escape_folder(folder)}/README.md",
        'ioc_hashes_url' => "https://raw.githubusercontent.com/RedDrip7/APT_Digital_Weapon/master/#{escape_folder(folder)}/#{escape_folder(folder)}_hash.md"
      }
    end

    manifest = {
      'source_name' => 'RedDrip7 APT_Digital_Weapon',
      'source_dataset_url' => SOURCE_DATASET_URL,
      'source_api_root' => @options[:api_root],
      'retrieved_at' => Time.now.utc.iso8601,
      'record_count' => records.length,
      'source_checksum_sha256' => Digest::SHA256.hexdigest(JSON.generate(records)),
      'folders_file' => 'folders.json'
    }

    File.write(File.join(@options[:output], 'folders.json'), JSON.pretty_generate(records) + "\n")
    File.write(File.join(@options[:output], 'manifest.yml'), YAML.dump(manifest))
    puts "Fetched #{records.length} folders into #{@options[:output]}"
  end

  def process_snapshot(write)
    snapshot_file = File.directory?(@options[:snapshot]) ? File.join(@options[:snapshot], 'folders.json') : @options[:snapshot]
    folders = JSON.parse(File.read(snapshot_file))
    folder_by_key = folders.each_with_object({}) { |f, memo| memo[f['folder_key']] = f }

    actors = ActorStore.load_all
    matches = []
    unmatched = []

    actors.each do |actor|
      aliases = Array(actor['aliases']).map(&:to_s)
      candidates = ([actor['name'].to_s] + aliases).map { |x| normalize(x) }
      record = candidates.map { |key| folder_by_key[key] }.compact.first
      if record
        matches << [actor, record]
      else
        unmatched << actor['name']
      end
    end

    updates = 0
    if write
      matches.each do |actor, record|
        actor['provenance'] ||= {}
        actor['provenance']['reddrip7_apt_digital_weapon'] = {
          'actor_folder' => record['folder'],
          'actor_readme_url' => record['actor_readme_url'],
          'ioc_hashes_url' => record['ioc_hashes_url'],
          'source_attribution' => SOURCE_ATTRIBUTION,
          'source_dataset_url' => SOURCE_DATASET_URL,
          'source_retrieved_at' => Time.now.utc.iso8601
        }
        ActorStore.save_actor(actor)
        updates += 1
      end
    end

    report = {
      'source' => 'reddrip7-apt-digital-weapon',
      'snapshot' => @options[:snapshot],
      'matched_actors' => matches.length,
      'unmatched_actors' => unmatched.length,
      'write' => write,
      'updated_actors' => updates,
      'sample_matches' => matches.first(25).map { |actor, record| { 'actor' => actor['name'], 'folder' => record['folder'] } }
    }

    File.write(@options[:report_json], JSON.pretty_generate(report) + "\n") if @options[:report_json]
    puts "Matched #{matches.length} actors#{write ? "; updated #{updates}" : ''}."
  end

  def http_get_json(url)
    uri = URI(url)
    req = Net::HTTP::Get.new(uri)
    req['User-Agent'] = 'ThreatActor.info importer'
    res = Net::HTTP.start(uri.host, uri.port, use_ssl: uri.scheme == 'https') { |http| http.request(req) }
    raise "HTTP #{res.code} for #{url}" unless res.is_a?(Net::HTTPSuccess)

    JSON.parse(res.body)
  end

  def normalize(value)
    value.to_s.downcase.gsub(/[^a-z0-9]/, '')
  end

  def escape_folder(value)
    value.to_s.gsub(' ', '%20')
  end
end

RedDrip7AptDigitalWeaponImporter.new(ARGV).run
