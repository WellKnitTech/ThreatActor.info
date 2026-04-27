#!/usr/bin/env ruby

# frozen_string_literal: true

require 'fileutils'
require 'json'
require 'optparse'
require 'set'
require 'time'
require 'yaml'
require_relative 'actor_store'

class AnalystNotesImporter
  DEFAULT_NOTES_DIR = '_data/analyst_notes'.freeze
  DEFAULT_OVERRIDES_FILE = 'data/imports/analyst-notes/mapping_overrides.yml'.freeze
  SOURCE_NAME = 'AnalystNotes'.freeze
  SOURCE_ATTRIBUTION = 'Analyst notes are manually curated observations and contextual analysis.'.freeze

  # Supported note types and their target fields
  NOTE_TYPES = {
    'targeted_countries' => { field: 'targeted_victims', array: true, split: true },
    'targeted_sectors' => { field: 'sector_focus', array: true, split: true },
    'operations' => { field: 'operations', array: true, split: true },
    'malware' => { field: 'malware', array: true, split: true },
    'tools' => { field: 'malware', array: true, split: true },
    'ttps' => { field: 'ttps', array: true, split: true },
    'cves' => { field: 'cisa_kev_cves', array: true, split: true },
    'urls' => { field: 'urls', array: true, split: true },
    'domains' => { field: 'domains', array: true, split: true },
    'ips' => { field: 'ips', array: true, split: true },
    'hashes' => { field: 'hashes', array: true, split: true },
    'campaigns' => { field: 'campaigns', array: true, split: true },
    'general' => { field: 'analyst_notes', array: false, split: false }
  }.freeze

  def initialize(argv)
    @argv = argv.dup
    @command = @argv.shift
    @options = {
      notes_dir: DEFAULT_NOTES_DIR,
      actor_filters: [],
      limit: nil,
      overrides_file: DEFAULT_OVERRIDES_FILE,
      report_json: nil,
      write: false
    }
    @overrides = {
      excluded_actors: [],
      match_overrides: {}
    }
  end

  def run
    case @command
    when 'init'
      parse_init_options
      initialize_actor_notes
    when 'new'
      parse_new_actor_options
      create_actor_from_notes
    when 'plan'
      parse_import_options
      load_overrides
      import_from_notes_dir
    when 'import'
      parse_import_options
      @options[:write] = true
      load_overrides
      import_from_notes_dir
    else
      puts usage
      exit 1
    end
  end

  private

  def usage
    <<~TEXT
      Usage:
        ruby scripts/import-analyst-notes.rb init --actor ACTOR_NAME
        ruby scripts/import-analyst-notes.rb new --actor ACTOR_NAME [options]
        ruby scripts/import-analyst-notes.rb plan [options]
        ruby scripts/import-analyst-notes.rb import [options]

      Commands:
        init  - Create analyst notes file for a specific actor
        new   - Create a new actor from analyst notes (if actor doesn't exist)
        plan  - Preview analyst notes that would be applied
        import - Apply analyst notes to actors

      Supported note types:
        targeted_countries, targeted_sectors, operations, malware, tools,
        ttps, cves, urls, domains, ips, hashes, campaigns, general

      Notes:
        - Each threat actor has their own notes file in #{DEFAULT_NOTES_DIR}/
        - Use 'new' to create entirely new actors from analyst notes
        - Structured notes are split across appropriate TA page fields
        - Plain text notes are added to analyst_notes field
    TEXT
  end

  def parse_init_options
    parser = OptionParser.new do |opts|
      opts.banner = 'Usage: ruby scripts/import-analyst-notes.rb init --actor ACTOR_NAME'
      opts.on('--actor NAME', 'Actor name to initialize') { |value| @options[:actor_name] = value }
    end

    parser.parse!(@argv)
    unless @options[:actor_name]
      warn 'An actor name is required for init.'
      puts usage
      exit 1
    end
  end

  def parse_new_actor_options
    parser = OptionParser.new do |opts|
      opts.banner = 'Usage: ruby scripts/import-analyst-notes.rb new --actor ACTOR_NAME [options]'
      opts.on('--actor NAME', 'Actor name to create') { |value| @options[:actor_name] = value }
      opts.on('--description DESC', 'Brief description') { |value| @options[:description] = value }
      opts.on('--country CODE', 'Country code') { |value| @options[:country] = value }
      opts.on('--url PATH', 'URL path') { |value| @options[:url] = value }
      opts.on('--risk LEVEL', 'Risk level') { |value| @options[:risk_level] = value }
      opts.on('--force', 'Overwrite if exists') { |value| @options[:force] = true }
    end

    parser.parse!(@argv)
    unless @options[:actor_name]
      warn 'An actor name is required for new.'
      puts usage
      exit 1
    end
  end

  def create_actor_from_notes
    return if actor_exists?(@options[:actor_name]) && !@options[:force]

    name = @options[:actor_name]
    url = @options[:url] || "/#{slugify(name)}"
    description = @options[:description] || "Manually created threat actor based on analyst research."

    actor = {
      'name' => name,
      'description' => description,
      'url' => url,
      'country' => @options[:country],
      'risk_level' => @options[:risk_level],
      'source_name' => 'Analyst Notes',
      'source_attribution' => 'Manually created by analyst'
    }

    actor.reject! { |_, v| v.nil? || (v.respond_to?(:empty?) && v.empty?) }

    actor_file = File.join('_data/actors', "#{slugify(url)}.yml")
    File.write(actor_file, YAML.dump(actor))

    # Create markdown page
    page_file = File.join('_threat_actors', "#{slugify(url)}.md")
    page_content = build_actor_page(actor)
    File.write(page_file, page_content)

    puts "Created actor: #{actor_file}"
    puts "Created page: #{page_file}"
    puts "\nEdit the notes file to add structured data:"
    puts "  _data/analyst_notes/#{slugify(name)}.yml"
  end

  def actor_exists?(name)
    name_key = slugify(name)
    File.exist?(File.join('_data/actors', "#{name_key}.yml"))
  end

  def slugify(value)
    value.to_s.downcase.gsub(/[^a-z0-9]+/, '-').gsub(/^-|-$/, '')
  end

  def build_actor_page(actor)
    <<~YAML
---
layout: threat_actor
title: "#{actor['name']}"
description: "#{actor['description']}"
permalink: #{actor['url']}/
---

## Introduction

#{actor['description']}

## Activities and Tactics

## Notable Campaigns

## Tactics, Techniques, and Procedures (TTPs)

## Notable Indicators of Compromise (IOCs)

## Malware and Tools

## Attribution and Evidence

## References
    YAML
  end

  def parse_import_options
    parser = OptionParser.new do |opts|
      opts.banner = 'Usage: ruby scripts/import-analyst-notes.rb plan|import [options]'
      opts.on('--notes-dir DIR', 'Directory with per-actor notes files') { |value| @options[:notes_dir] = value }
      opts.on('--actor NAME', 'Restrict to a specific actor (repeatable)') { |value| @options[:actor_filters] << value }
      opts.on('--limit N', Integer, 'Process only the first N matched actors') { |value| @options[:limit] = value }
      opts.on('--report-json PATH', 'Write a machine-readable report') { |value| @options[:report_json] = value }
      opts.on('--overrides PATH', 'Override mapping file') { |value| @options[:overrides_file] = value }
    end

    parser.parse!(@argv)
  end

  def initialize_actor_notes
    FileUtils.mkdir_p(DEFAULT_NOTES_DIR)
    actor_name = @options[:actor_name]
    actor_slug = normalize_key(actor_name).downcase
    notes_file = File.join(DEFAULT_NOTES_DIR, "#{actor_slug}.yml")

    if File.exist?(notes_file)
      puts "Analyst notes already exist for #{actor_name}: #{notes_file}"
      exit 0
    end

    template = {
      'actor_name' => actor_name,
      'last_updated' => Time.now.utc.strftime('%Y-%m-%d'),
      'note_blocks' => []
    }

    File.write(notes_file, YAML.dump(template))
    puts "Created analyst notes file: #{notes_file}"
    puts "Edit this file to add structured note blocks."
  end

  def import_from_notes_dir
    notes_files = load_notes_files
    existing_actors = ActorStore.load_all
    actor_lookup, actor_slug_lookup, existing_by_name = build_actor_indexes(existing_actors)
    evaluations = evaluate_notes_files(notes_files, actor_lookup, actor_slug_lookup, existing_by_name)
    actor_updates = build_actor_updates(evaluations, existing_by_name)
    actor_updates.select! { |name, _| actor_filter_match?(name) } unless @options[:actor_filters].empty?
    actor_updates = actor_updates.first(@options[:limit]).to_h if @options[:limit]

    report = build_report(evaluations, actor_updates)
    File.write(@options[:report_json], JSON.pretty_generate(report) + "\n") if @options[:report_json]
    print_report(report)

    return unless @options[:write]

    apply_updates(actor_updates, existing_actors)
    ActorStore.save_all(existing_actors)
    puts "Applied analyst notes updates to #{actor_updates.length} actors"
  end

  def load_notes_files
    return [] unless File.directory?(@options[:notes_dir])

    Dir.glob(File.join(@options[:notes_dir], '*.yml')).map do |path|
      safe_load_yaml_file(path)
    end.compact
  rescue Errno::ENOENT
    warn "Notes directory not found: #{@options[:notes_dir]}"
    []
  end

  def build_actor_indexes(existing_actors)
    actor_lookup = Hash.new { |hash, key| hash[key] = Set.new }
    actor_slug_lookup = {}
    existing_by_name = {}

    existing_actors.each do |actor|
      name = actor['name']
      next if name.to_s.empty?

      existing_by_name[name] = actor
      actor_slug_lookup[normalize_key(actor['url'].to_s.sub(%r{^/}, ''))] = name unless actor['url'].to_s.empty?
      actor_aliases(actor).each do |alias_name|
        key = normalize_phrase(alias_name)
        next if key.empty? || skip_alias_for_matching?(key)

        actor_lookup[key] << name
      end
    end

    [actor_lookup, actor_slug_lookup, existing_by_name]
  end

  def actor_aliases(actor)
    ([actor['name']] + Array(actor['aliases'])).map { |value| value.to_s.strip }.reject(&:empty?).uniq
  end

  def skip_alias_for_matching?(value)
    token_count = value.split.length
    return false if value.match?(/\b(?:apt|fin|uac|unc|ta|dev|storm|tag)\b/) || value.match?(/\d/)

    token_count == 1 && value.length < 4
  end

  def evaluate_notes_files(notes_files, actor_lookup, actor_slug_lookup, existing_by_name)
    notes_files.filter_map do |notes_file|
      actor_name = notes_file['actor_name'].to_s.strip
      next if actor_name.empty?

      explicit_match = @overrides[:match_overrides][normalize_key(actor_name)]
      matched_names = if explicit_match
                    [explicit_match]
                  else
                    infer_actor_matches(actor_name, actor_lookup, actor_slug_lookup).to_a.sort
                  end

      action = if matched_names.empty?
                'unmatched'
              elsif matched_names.length == 1 && existing_by_name.key?(matched_names.first)
                'matched'
              else
                'ambiguous'
              end

      note_blocks = Array(notes_file['note_blocks']).compact

      {
        'actor_name' => actor_name,
        'matched_actor_names' => matched_names,
        'action' => action,
        'note_blocks' => note_blocks,
        'last_updated' => notes_file['last_updated']
      }
    end
  end

  def infer_actor_matches(actor_name, actor_lookup, actor_slug_lookup)
    matches = Set.new
    normalized = normalize_phrase(actor_name)
    words = normalized.split

    actor_lookup[normalized].each { |name| matches << name }
    matches << actor_slug_lookup[normalize_key(actor_name)]

    (1..[4, words.length].min).each do |size|
      words.each_cons(size) do |ngram|
        key = ngram.join(' ')
        next if key.empty?

        actor_lookup[key].each { |name| matches << name }
      end
    end

    matches.delete(nil)
    matches
  end

  def build_actor_updates(evaluations, existing_by_name)
    grouped = evaluations.select { |record| record['action'] == 'matched' }.group_by { |record| record['matched_actor_names'].first }

    grouped.each_with_object({}) do |(actor_name, records), memo|
      actor = existing_by_name[actor_name]
      next unless actor

      updates = {
        targeted_victims: [],
        sector_focus: [],
        operations: [],
        malware: [],
        ttps: [],
        cisa_kev_cves: [],
        urls: [],
        domains: [],
        ips: [],
        hashes: [],
        campaigns: [],
        analyst_notes: []
      }

      records.each do |record|
        record['note_blocks'].each do |block|
          process_note_block(block, updates)
        end
      end

      # Clean up empty arrays
      updates.each { |_, v| v.uniq! }

      memo[actor_name] = {
        actor: actor,
        updates: updates,
        last_updated: records.map { |r| r['last_updated'] }.compact.max
      }
    end
  end

  def process_note_block(block, updates)
    type = block['type'].to_s.strip.downcase
    values = Array(block['values']).map(&:to_s).map(&:strip).reject(&:empty?)
    content = block['content'].to_s.strip

    return if values.empty? && content.empty?

    case type
    when 'targeted_countries'
      updates[:targeted_victims].concat(values)
    when 'targeted_sectors'
      updates[:sector_focus].concat(values)
    when 'operations'
      updates[:operations].concat(values)
    when 'malware', 'tools'
      values.each { |v| updates[:malware] << "Analyst: #{v}" }
    when 'ttps'
      updates[:ttps].concat(values)
    when 'cves'
      updates[:cisa_kev_cves].concat(values)
    when 'urls'
      updates[:urls].concat(values)
    when 'domains'
      updates[:domains].concat(values)
    when 'ips'
      updates[:ips].concat(values)
    when 'hashes'
      updates[:hashes].concat(values)
    when 'campaigns'
      updates[:campaigns].concat(values)
    when 'general'
      updates[:analyst_notes] << content unless content.empty?
    else
      # Unknown type, treat as general note
      updates[:analyst_notes] << content unless content.empty?
    end
  end

  def build_report(evaluations, actor_updates)
    {
      timestamp: Time.now.utc.iso8601,
      source: SOURCE_NAME,
      notes_files_processed: evaluations.length,
      matched_files: evaluations.count { |r| r['action'] == 'matched' },
      ambiguous_files: evaluations.count { |r| r['action'] == 'ambiguous' },
      unmatched_files: evaluations.count { |r| r['action'] == 'unmatched' },
      actors_with_updates: actor_updates.length,
      actor_updates: actor_updates.map do |actor_name, payload|
        {
          name: actor_name,
          updates_summary: payload[:updates].each_with_object({}) do |(k, v), memo|
            memo[k] = v.length if v.any?
          end
        }
      end,
      ambiguous_files: evaluations.select { |r| r['action'] == 'ambiguous' }.first(50),
      unmatched_files: evaluations.select { |r| r['action'] == 'unmatched' }.first(50)
    }
  end

  def print_report(report)
    puts "\n=== Analyst Notes Import Plan ==="
    puts "Notes files processed: #{report[:notes_files_processed]}"
    puts "Matched files: #{report[:matched_files]}"
    puts "Ambiguous files: #{report[:ambiguous_files]}"
    puts "Unmatched files: #{report[:unmatched_files]}"
    puts "Actors with updates: #{report[:actors_with_updates]}"

    report[:actor_updates].first(20).each do |entry|
      puts "\nUPDATE: #{entry[:name]}"
      entry[:updates_summary].each do |field, count|
        puts "  #{field}: #{count}"
      end
    end

    puts "\n=== Run with import to apply ===" unless @options[:write]
  end

  def apply_updates(actor_updates, existing_actors)
    existing_by_name = existing_actors.each_with_object({}) { |actor, memo| memo[actor['name']] = actor }

    actor_updates.each do |actor_name, payload|
      actor = existing_by_name[actor_name]
      next unless actor

      updates = payload[:updates]

      # Apply each update to the appropriate field
      if updates[:targeted_victims].any?
        actor['targeted_victims'] ||= []
        actor['targeted_victims'] = (actor['targeted_victims'] + updates[:targeted_victims]).uniq
      end

      if updates[:sector_focus].any?
        actor['sector_focus'] ||= []
        actor['sector_focus'] = (actor['sector_focus'] + updates[:sector_focus]).uniq
      end

      if updates[:operations].any?
        actor['operations'] ||= []
        actor['operations'] = (actor['operations'] + updates[:operations]).uniq
      end

      if updates[:malware].any?
        actor['malware'] ||= []
        actor['malware'] = (actor['malware'] + updates[:malware]).uniq
      end

      if updates[:ttps].any?
        actor['ttps'] ||= []
        actor['ttps'] = (actor['ttps'] + updates[:ttps]).uniq
      end

      if updates[:cisa_kev_cves].any?
        actor['cisa_kev_cves'] ||= []
        actor['cisa_kev_cves'] = (actor['cisa_kev_cves'] + updates[:cisa_kev_cves]).uniq
      end

      if updates[:urls].any?
        actor['urls'] ||= []
        actor['urls'] = (actor['urls'] + updates[:urls]).uniq
      end

      if updates[:domains].any?
        actor['domains'] ||= []
        actor['domains'] = (actor['domains'] + updates[:domains]).uniq
      end

      if updates[:ips].any?
        actor['ips'] ||= []
        actor['ips'] = (actor['ips'] + updates[:ips]).uniq
      end

      if updates[:hashes].any?
        actor['hashes'] ||= []
        actor['hashes'] = (actor['hashes'] + updates[:hashes]).uniq
      end

      if updates[:campaigns].any?
        actor['campaigns'] ||= []
        actor['campaigns'] = (actor['campaigns'] + updates[:campaigns]).uniq
      end

      # Collect general analyst notes
      general_notes_text = updates[:analyst_notes].join("\n\n")
      existing_notes = actor['analyst_notes'].to_s.strip
      if updates[:analyst_notes].any?
        if existing_notes.empty?
          actor['analyst_notes'] = general_notes_text
        else
          actor['analyst_notes'] = "#{existing_notes}\n\n---\n\n#{general_notes_text}"
        end
      end

      # Update provenance
      actor['provenance'] ||= {}
      actor['provenance']['analyst_notes'] = {
        'source_retrieved_at' => Time.now.utc.strftime('%Y-%m-%dT%H:%M:%SZ'),
        'last_imported' => payload[:last_updated]
      }

      # Set source attribution if not already set
      actor['source_name'] ||= SOURCE_NAME
      actor['source_attribution'] ||= SOURCE_ATTRIBUTION

      # Update last_updated in the notes file
      update_notes_file_last_updated(actor_name, payload[:last_updated])
    end
  end

  def update_notes_file_last_updated(actor_name, last_updated)
    actor_slug = normalize_key(actor_name).downcase
    notes_file = File.join(DEFAULT_NOTES_DIR, "#{actor_slug}.yml")
    return unless File.exist?(notes_file)

    notes = safe_load_yaml_file(notes_file)
    return unless notes

    notes['last_imported'] = last_updated || Time.now.utc.strftime('%Y-%m-%d')
    File.write(notes_file, YAML.dump(notes))
  end

  def actor_filter_match?(actor_name)
    filters = @options[:actor_filters].map { |value| normalize_key(value) }
    filters.include?(normalize_key(actor_name))
  end

  def load_overrides
    return unless File.exist?(@options[:overrides_file])

    payload = safe_load_yaml_file(@options[:overrides_file]) || {}
    @overrides[:excluded_actors] = Array(payload['excluded_actors']).map { |value| normalize_key(value) }.uniq
    @overrides[:match_overrides] = normalize_override_hash(payload['match_overrides'], preserve_values: true)
  end

  def normalize_override_hash(value, preserve_values: false)
    (value || {}).each_with_object({}) do |(key, mapped_value), memo|
      normalized_key = normalize_key(key)
      next if normalized_key.empty?

      memo[normalized_key] = preserve_values ? mapped_value : normalize_key(mapped_value)
    end
  end

  def normalize_phrase(value)
    sanitize_text(value).downcase.gsub(/[^a-z0-9]+/, ' ').strip
  end

  def normalize_key(value)
    normalize_phrase(value).gsub(' ', '')
  end

  def sanitize_text(value)
    value.to_s.gsub(/\s+/, ' ').strip
  end

  def safe_load_yaml_file(path)
    return nil unless File.exist?(path)

    YAML.safe_load(File.read(path), permitted_classes: [], aliases: false)
  end
end

AnalystNotesImporter.new(ARGV).run if __FILE__ == $PROGRAM_NAME