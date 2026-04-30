#!/usr/bin/env ruby

# frozen_string_literal: true

require 'csv'
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

class EtdaThaicertImporter
  PAGE_DIR = '_threat_actors'.freeze
  DEFAULT_SNAPSHOT_ROOT = 'data/imports/etda-thaicert'.freeze
  DEFAULT_OVERRIDES_FILE = 'data/imports/etda-thaicert/mapping_overrides.yml'.freeze
  SOURCE_NAME = 'ETDA / ThaiCERT Threat Group Cards'.freeze
  SOURCE_URL = 'https://apt.etda.or.th/cgi-bin/getmisp.cgi?o=g'.freeze
  SOURCE_MIRROR_URL = 'https://huggingface.co/datasets/threatactor-info/etda-thaicert-threat-groups/raw/main/groups.json'.freeze
  SOURCE_REPOSITORY = 'https://apt.etda.or.th/'.freeze
  MANUAL_SOURCE_NAMES = ['Manual Entry', 'Analyst Notes'].freeze
  SOURCE_ATTRIBUTION = 'Contains data derived from ETDA/ThaiCERT Threat Group Cards (https://apt.etda.or.th/), adapted with attribution for research and enrichment.'.freeze

  REQUIRED_HEADINGS = [
    'Introduction',
    'Activities and Tactics',
    'Notable Campaigns',
    'Tactics, Techniques, and Procedures (TTPs)',
    'Notable Indicators of Compromise (IOCs)',
    'Malware and Tools',
    'Attribution and Evidence',
    'References'
  ].freeze

  def initialize(argv)
    @argv = argv.dup
    @command = @argv.shift
    @options = {
      source_url: SOURCE_URL,
      mirror_url: SOURCE_MIRROR_URL,
      output: nil,
      snapshot: nil,
      actor_filters: [],
      limit: nil,
      overrides_file: DEFAULT_OVERRIDES_FILE,
      report_json: nil,
      write: false,
      force: false,
      new_only: false
    }
    @overrides = {
      excluded_group_keys: [],
      match_overrides: {},
      display_name_overrides: {},
      country_overrides: {},
      alias_drop_list: []
    }
  end

  def run
    case @command
    when 'fetch'
      parse_fetch_options
      load_overrides
      fetch_snapshot
    when 'plan'
      parse_import_options
      load_overrides
      import_snapshot
    when 'import'
      parse_import_options
      @options[:write] = true
      load_overrides
      import_snapshot
    else
      puts usage
      exit 1
    end
  end

  private

  def usage
    <<~TEXT
      Usage:
        ruby scripts/import-etda-thaicert.rb fetch [options]
        ruby scripts/import-etda-thaicert.rb plan --snapshot PATH [options]
        ruby scripts/import-etda-thaicert.rb import --snapshot PATH [options]

      Notes:
        - Supports snapshot-first workflow for deterministic imports.
        - Uses conservative matching and review buckets for ambiguous records.
        - Does additive updates by default; use --force for protected fields.
    TEXT
  end

  def parse_fetch_options
    parser = OptionParser.new do |opts|
      opts.banner = 'Usage: ruby scripts/import-etda-thaicert.rb fetch [options]'
      opts.on('--source-url URL', 'Primary ETDA dataset URL') { |value| @options[:source_url] = value }
      opts.on('--mirror-url URL', 'Mirror dataset URL (fallback)') { |value| @options[:mirror_url] = value }
      opts.on('--output DIR', 'Snapshot output directory') { |value| @options[:output] = value }
      opts.on('--limit N', Integer, 'Fetch only the first N records after normalization') { |value| @options[:limit] = value }
      opts.on('--overrides PATH', 'Override mapping file') { |value| @options[:overrides_file] = value }
    end
    parser.parse!(@argv)
    @options[:output] ||= File.join(DEFAULT_SNAPSHOT_ROOT, Time.now.utc.strftime('%Y-%m-%d'))
  end

  def parse_import_options
    parser = OptionParser.new do |opts|
      opts.banner = 'Usage: ruby scripts/import-etda-thaicert.rb plan|import --snapshot PATH [options]'
      opts.on('--snapshot PATH', 'Snapshot directory or groups.json path') { |value| @options[:snapshot] = value }
      opts.on('--actor NAME', 'Restrict to specific actor/group (repeatable)') { |value| @options[:actor_filters] << value }
      opts.on('--limit N', Integer, 'Process only the first N candidate records') { |value| @options[:limit] = value }
      opts.on('--report-json PATH', 'Write machine-readable report') { |value| @options[:report_json] = value }
      opts.on('--overrides PATH', 'Override mapping file') { |value| @options[:overrides_file] = value }
      opts.on('--force', 'Allow protected field updates') { @options[:force] = true }
      opts.on('--new-only', 'Only create new actors; no updates to existing') { @options[:new_only] = true }
    end
    parser.parse!(@argv)
    return if @options[:snapshot]

    warn 'A snapshot path is required for plan/import.'
    exit 1
  end

  def fetch_snapshot
    FileUtils.mkdir_p(@options[:output])
    payload, used_url = fetch_source_payload
    records = normalize_source_payload(payload)
    records = records.first(@options[:limit]) if @options[:limit]

    groups_path = File.join(@options[:output], 'groups.json')
    manifest_path = File.join(@options[:output], 'manifest.yml')

    File.write(groups_path, JSON.pretty_generate(records) + "\n")
    File.write(manifest_path, YAML.dump({
                                         'source_name' => SOURCE_NAME,
                                         'source_repository' => SOURCE_REPOSITORY,
                                         'source_url' => used_url,
                                         'retrieved_at' => Time.now.utc.iso8601,
                                         'record_count' => records.length,
                                         'source_checksum_sha256' => Digest::SHA256.hexdigest(JSON.generate(records)),
                                         'groups_file' => 'groups.json'
                                       }))

    puts "Fetched #{records.length} ETDA/ThaiCERT records into #{@options[:output]}"
  end

  def fetch_source_payload
    [@options[:source_url], @options[:mirror_url]].uniq.each do |url|
      next if sanitize_text(url).empty?

      payload = http_get(url)
      return [payload, url]
    rescue StandardError => e
      warn "Fetch failed for #{url}: #{e.message}"
    end
    raise 'Failed to fetch ETDA dataset from source and mirror.'
  end

  def import_snapshot
    records = load_snapshot_records
    records = filter_records(records)
    records = records.first(@options[:limit]) if @options[:limit]

    existing_actors = ActorStore.load_all
    existing_pages = load_pages
    evaluation = evaluate_records(records, existing_actors)

    report = build_report(evaluation)
    File.write(@options[:report_json], JSON.pretty_generate(report) + "\n") if @options[:report_json]
    print_report(evaluation)

    return unless @options[:write]

    apply_results(evaluation, existing_actors, existing_pages)
    ActorStore.save_all(existing_actors)
    puts "Applied #{evaluation.count { |item| item[:action] == 'create' }} creates and #{evaluation.count { |item| item[:action] == 'update' }} updates"
  end

  def load_snapshot_records
    groups_path = if File.directory?(@options[:snapshot])
                    File.join(@options[:snapshot], 'groups.json')
                  else
                    @options[:snapshot]
                  end
    payload = JSON.parse(File.read(groups_path))
    normalize_source_payload(payload)
  rescue Errno::ENOENT
    warn "Snapshot file not found: #{groups_path}"
    exit 1
  end

  def filter_records(records)
    return records if @options[:actor_filters].empty?

    filters = @options[:actor_filters].map { |value| normalize_key(value) }
    records.select do |record|
      candidates = [record[:canonical_key], normalize_key(record[:url])]
      candidates.concat(record[:aliases].map { |value| normalize_key(value) })
      (candidates.compact & filters).any?
    end
  end

  def evaluate_records(records, existing_actors)
    index = build_match_index(existing_actors)
    records.map { |record| build_evaluation(record, match_record(record, index), existing_actors) }
  end

  def build_match_index(existing_actors)
    index = Hash.new { |hash, key| hash[key] = Set.new }
    existing_actors.each_with_index do |actor, position|
      keys_for_actor(actor).each { |key| index[key] << position }
    end
    index
  end

  def keys_for_actor(actor)
    ([actor['name']] + Array(actor['aliases']) + [actor['url']]).filter_map do |value|
      key = normalize_key(value)
      key unless key.empty?
    end.uniq
  end

  def match_record(record, index)
    keys = [record[:canonical_key], normalize_key(record[:url])]
    keys.concat(record[:aliases].map { |value| normalize_key(value) })
    keys.compact!
    keys.uniq!
    keys.reject!(&:empty?)
    matches = keys.flat_map { |key| index[key].to_a }.uniq
    return nil if matches.empty?
    return { confidence: 'high', position: matches.first } if matches.length == 1

    { confidence: 'ambiguous', positions: matches }
  end

  def build_evaluation(record, match, existing_actors)
    if @overrides[:excluded_group_keys].include?(record[:canonical_key])
      return {
        action: 'skip',
        reason: 'excluded',
        record: record
      }
    end

    unless match
      return {
        action: 'create',
        record: record,
        actor: build_new_actor(record)
      }
    end

    if match[:confidence] == 'ambiguous'
      return {
        action: 'review',
        reason: 'ambiguous-match',
        record: record,
        matches: match[:positions].map { |position| existing_actors[position]['name'] }.sort
      }
    end

    existing_actor = existing_actors[match[:position]]
    updates = @options[:new_only] ? {} : build_actor_updates(existing_actor, record)
    {
      action: updates.empty? ? 'skip' : 'update',
      reason: updates.empty? ? 'no-changes' : nil,
      record: record,
      match_position: match[:position],
      existing_name: existing_actor['name'],
      updates: updates
    }
  end

  def build_new_actor(record)
    {
      'name' => record[:display_name],
      'aliases' => record[:aliases],
      'description' => record[:description],
      'url' => record[:url],
      'country' => record[:country],
      'sector_focus' => record[:sector_focus],
      'operations' => record[:operations],
      'malware' => record[:malware],
      'first_seen' => record[:first_seen],
      'last_activity' => record[:last_activity],
      'source_name' => SOURCE_NAME,
      'source_attribution' => SOURCE_ATTRIBUTION,
      'source_record_url' => record[:source_record_url],
      'provenance' => { 'etda_thaicert' => build_provenance(record) }
    }.reject { |_key, value| value.nil? || value == [] || value == '' }
  end

  def build_actor_updates(existing_actor, record)
    updates = {}

    aliases = (Array(existing_actor['aliases']) + record[:aliases])
              .map { |value| sanitize_text(value) }
              .reject(&:empty?)
              .uniq
              .sort
    updates['aliases'] = aliases if aliases != Array(existing_actor['aliases'])

    merge_array_field(updates, existing_actor, 'sector_focus', record[:sector_focus])
    merge_array_field(updates, existing_actor, 'operations', record[:operations])

    merge_malware(updates, existing_actor, record[:malware])

    updates['country'] = record[:country] if existing_actor['country'].to_s.empty? && !record[:country].to_s.empty?
    updates['first_seen'] = record[:first_seen] if existing_actor['first_seen'].to_s.empty? && !record[:first_seen].to_s.empty?
    if !record[:last_activity].to_s.empty? && newer_year?(existing_actor['last_activity'], record[:last_activity])
      updates['last_activity'] = record[:last_activity]
    end

    if @options[:force]
      merged_description = merge_description_with_source(existing_actor['description'], record[:description], SOURCE_NAME, record[:source_record_url])
      updates['description'] = merged_description if !merged_description.nil? && merged_description != existing_actor['description']
      updates['name'] = record[:display_name] if !record[:display_name].to_s.empty? && record[:display_name] != existing_actor['name']
    end

    if existing_actor['source_name'].to_s.empty?
      updates['source_name'] = SOURCE_NAME
      updates['source_attribution'] = SOURCE_ATTRIBUTION
    end

    # Handle takeover: if manual entry found by importer, convert manual data to analyst notes
    if MANUAL_SOURCE_NAMES.include?(existing_actor['source_name'])
      updates = handle_manual_takeover(updates, existing_actor, record)
    end
    if !record[:source_record_url].to_s.empty? && (existing_actor['source_record_url'].to_s.empty? || existing_actor['source_name'] == SOURCE_NAME)
      updates['source_record_url'] = record[:source_record_url]
    end

    provenance = existing_actor['provenance'].is_a?(Hash) ? deep_dup_hash(existing_actor['provenance']) : {}
    etda_provenance = provenance['etda_thaicert'].is_a?(Hash) ? provenance['etda_thaicert'] : {}
    merged_etda = etda_provenance.merge(build_provenance(record))
    provenance['etda_thaicert'] = merged_etda
    updates['provenance'] = provenance if provenance != existing_actor['provenance']

    updates
  end

  def merge_array_field(updates, actor, field, values)
    return if values.nil? || values.empty?

    merged = (Array(actor[field]) + values).map { |value| sanitize_text(value) }.reject(&:empty?).uniq.sort
    updates[field] = merged if merged != Array(actor[field])
  end

  def merge_malware(updates, actor, incoming)
    return if incoming.nil? || incoming.empty?

    existing = Array(actor['malware'])
    existing_names = existing.filter_map { |entry| normalize_key(entry['name']) }.to_set
    merged = existing.map { |entry| entry.dup }
    incoming.each do |name|
      key = normalize_key(name)
      next if key.empty? || existing_names.include?(key)

      merged << { 'name' => name }
      existing_names << key
    end
    updates['malware'] = merged if merged != existing
  end

  def newer_year?(current_year, candidate_year)
    return true if current_year.to_s.empty?

    candidate_year.to_i > current_year.to_i
  end

  def merge_description_with_source(current_description, incoming_description, source_label, source_url)
    incoming = incoming_description.to_s.strip
    return nil if incoming.empty?

    current = current_description.to_s.strip
    return incoming if current.empty?

    heading = "### Source: #{source_label}"
    return nil if current.include?(heading)

    section = [heading, incoming, source_url.to_s.strip.empty? ? SOURCE_URL : source_url.to_s.strip].join("\n")
    [current, section].join("\n\n")
  end

  def build_provenance(record)
    {
      'source_dataset_url' => record[:source_dataset_url],
      'source_record_id' => record[:source_record_id],
      'source_record_url' => record[:source_record_url],
      'source_retrieved_at' => record[:source_retrieved_at],
      'mitre_group_ids' => record[:mitre_group_ids],
      'mitre_technique_ids' => record[:mitre_technique_ids],
      'source_transforms' => record[:source_transforms]
    }.reject { |_key, value| value.nil? || value == [] || value == '' }
  end

  # Handle takeover: convert manual entry to analyst notes when importer finds it
  def handle_manual_takeover(updates, existing_actor, record)
    # Extract existing manual data
    manual_description = existing_actor['description'].to_s.strip
    manual_country = existing_actor['country'].to_s.strip
    manual_aliases = Array(existing_actor['aliases'])
    manual_sectors = Array(existing_actor['sector_focus'])
    manual_targets = Array(existing_actor['targeted_victims'])
    manual_first_seen = existing_actor['first_seen'].to_s.strip
    manual_last_activity = existing_actor['last_activity'].to_s.strip
    manual_external_id = existing_actor['external_id'].to_s.strip
    manual_external_url = existing_actor['external_url'].to_s.strip
    manual_source_attribution = existing_actor['source_attribution'].to_s.strip

    # Generate analyst notes from manual entry
    analyst_notes_parts = []

    if !manual_description.empty?
      analyst_notes_parts << "Previous description: #{manual_description}"
    end

    if manual_aliases.any?
      analyst_notes_parts << "Previous aliases: #{manual_aliases.join(', ')}"
    end

    if manual_country
      analyst_notes_parts << "Previous country: #{manual_country}"
    end

    if manual_sectors.any?
      analyst_notes_parts << "Previous sectors: #{manual_sectors.join(', ')}"
    end

    if manual_targets.any?
      analyst_notes_parts << "Previous targets: #{manual_targets.join(', ')}"
    end

    if !manual_first_seen.empty? || !manual_last_activity.empty?
      activity = []
      activity << "first seen: #{manual_first_seen}" if !manual_first_seen.empty?
      activity << "last active: #{manual_last_activity}" if !manual_last_activity.empty?
      analyst_notes_parts << "Previous activity: #{activity.join(', ')}"
    end

    if !manual_external_id.empty?
      analyst_notes_parts << "Previous external ID: #{manual_external_id}"
    end

    if !manual_external_url.empty?
      analyst_notes_parts << "Previous reference: #{manual_external_url}"
    end

    # Add summary of what importer found
    analyst_notes_parts << ""
    analyst_notes_parts << "=== Automated import from #{record[:display_name] || record[:name]} ==="

    if record[:description] && !record[:description].empty?
      analyst_notes_parts << "New description sourced from #{SOURCE_NAME}"
    end

    # Merge all analyst notes
    analyst_notes = analyst_notes_parts.join("\n")
    if !analyst_notes.nil?
      existing_notes = existing_actor['analyst_notes'].to_s.strip
      if existing_notes.empty?
        updates['analyst_notes'] = analyst_notes
      else
        updates['analyst_notes'] = "#{existing_notes}\n\n---\n\n#{analyst_notes}"
      end
    end

    # Now apply the importer's updates (replace empty fields)
    updates['source_name'] = SOURCE_NAME
    updates['source_attribution'] = SOURCE_ATTRIBUTION

    # Import fields that were empty in manual entry
    merged_description = merge_description_with_source(existing_actor['description'], record[:description], SOURCE_NAME, record[:source_record_url])
    updates['description'] = merged_description if !merged_description.nil? && merged_description != existing_actor['description']
    updates['country'] = record[:country] if !record[:country].to_s.empty? && existing_actor['country'].to_s.empty?
    updates['name'] = record[:display_name] if !record[:display_name].to_s.empty? && record[:display_name] != existing_actor['name']

    # Merge aliases
    merged_aliases = (manual_aliases + record[:aliases]).uniq.sort
    updates['aliases'] = merged_aliases if merged_aliases != manual_aliases

    # Merge sectors if importer provides them and manual had some
    merge_array_field(updates, existing_actor, 'sector_focus', record[:sector_focus])

    puts "  TAKEOVER: Converted manual entry '#{existing_actor['name']}' to analyst notes"

    updates
  end

  def apply_results(evaluation, existing_actors, existing_pages)
    evaluation.each do |item|
      case item[:action]
      when 'create'
        actor = item[:actor]
        existing_actors << actor
        write_page(page_path_for(actor['url']), build_front_matter(actor), build_new_page_body(actor))
      when 'update'
        actor = existing_actors[item[:match_position]]
        actor.merge!(item[:updates])
        synchronize_existing_page(actor, existing_pages)
      end
    end
  end

  def synchronize_existing_page(actor, existing_pages)
    path = page_path_for(actor['url'])
    return unless File.exist?(path)

    page = existing_pages[path] || parse_page(path)
    updated_front_matter = page[:front_matter].merge(build_front_matter(actor))
    write_page(path, updated_front_matter, page[:body])
  rescue StandardError => e
    warn "Failed to synchronize page #{path}: #{e.message}"
  end

  def build_front_matter(actor)
    front_matter = {
      'layout' => 'threat_actor',
      'title' => actor['name'],
      'aliases' => actor['aliases'] || [],
      'description' => actor['description'],
      'permalink' => "#{actor['url']}/"
    }
    %w[country sector_focus first_seen last_activity risk_level external_id source_name source_attribution source_record_url].each do |field|
      value = actor[field]
      front_matter[field] = value unless value.nil? || value == [] || value == ''
    end
    front_matter
  end

  def build_new_page_body(actor)
    <<~MARKDOWN.strip
      ## Introduction
      #{actor['name']} is tracked by ETDA/ThaiCERT in public threat group card data. This profile was generated from an ETDA snapshot and should be enriched with additional source-backed analysis.

      ## Activities and Tactics
      Public reporting from ETDA/ThaiCERT identifies activity associated with this actor. Add analyst-curated campaign and tradecraft details here as they are validated.

      ## Notable Campaigns
      1. **ETDA/ThaiCERT Profile Presence**: The actor appears in ETDA/ThaiCERT threat group card data.
      2. **Seed Import**: This page originated from a reviewed ETDA importer snapshot.

      ## Tactics, Techniques, and Procedures (TTPs)
      MITRE ATT&CK group and technique hints may exist in provenance fields, but this section requires curated narrative before publication as canonical tradecraft.

      ## Notable Indicators of Compromise (IOCs)
      No volatile IOCs are imported automatically from ETDA/ThaiCERT. Add stable, source-backed indicators during manual curation.

      ## Malware and Tools
      Malware names may be captured in structured metadata. Expand with source-backed context and confidence notes.

      ## Attribution and Evidence
      This seed entry contains metadata derived from ETDA/ThaiCERT Threat Group Cards and adapted by this project for enrichment workflows.

      ## References
      1. [ETDA/ThaiCERT Threat Group Cards](https://apt.etda.or.th/)
      2. [Source record](#{actor['source_record_url'] || 'https://apt.etda.or.th/'})
    MARKDOWN
  end

  def build_report(evaluation)
    {
      timestamp: Time.now.utc.iso8601,
      source: SOURCE_NAME,
      total_candidates: evaluation.length,
      creates: evaluation.count { |item| item[:action] == 'create' },
      updates: evaluation.count { |item| item[:action] == 'update' },
      review: evaluation.count { |item| item[:action] == 'review' },
      skipped: evaluation.count { |item| item[:action] == 'skip' },
      actions: evaluation.map do |item|
        {
          action: item[:action],
          reason: item[:reason],
          name: item.dig(:record, :display_name),
          url: item.dig(:record, :url),
          existing_name: item[:existing_name],
          matches: item[:matches],
          update_fields: item[:updates]&.keys
        }
      end
    }
  end

  def print_report(evaluation)
    grouped = evaluation.group_by { |item| item[:action] }
    puts "Create: #{grouped.fetch('create', []).length}"
    puts "Update: #{grouped.fetch('update', []).length}"
    puts "Review: #{grouped.fetch('review', []).length}"
    puts "Skip: #{grouped.fetch('skip', []).length}"

    evaluation.each do |item|
      case item[:action]
      when 'create'
        puts "[CREATE] #{item[:actor]['name']} -> #{item[:actor]['url']}"
      when 'update'
        puts "[UPDATE] #{item[:existing_name]} (#{item[:updates].keys.join(', ')})"
      when 'review'
        puts "[REVIEW] #{item[:record][:display_name]} -> #{item[:matches].join(', ')}"
      when 'skip'
        puts "[SKIP] #{item[:record][:display_name]} (#{item[:reason]})"
      end
    end
  end

  def normalize_source_payload(payload)
    records = if payload.is_a?(Array)
                payload
              elsif payload.is_a?(Hash)
                # Handle MISP galaxy format with "values" array
                payload['values'] || payload['data'] || payload['groups'] || payload['cards'] || payload['results'] || payload['value'] || payload.values.find { |v| v.is_a?(Array) } || []
              else
                []
              end
    Array(records).filter_map { |record| normalize_record(record) }
  end

  def normalize_record(record)
    return nil unless record.is_a?(Hash)

    # Handle both direct format and MISP galaxy format (value/description/meta)
    raw_name = first_non_empty(record['name'], record['group_name'], record['group'], record['title'], record['actor'], record['value'])
    raw_name = first_non_empty(record[:name], record[:group_name], record[:group], record[:title], record[:actor], record[:value]) if raw_name.nil?
    raw_name = sanitize_text(raw_name)
    return nil if raw_name.empty?

    canonical = normalize_key(raw_name)
    return nil if canonical.empty?
    return nil if @overrides[:excluded_group_keys].include?(canonical)

    display_name = @overrides[:display_name_overrides][canonical] || raw_name
    
    # Handle MISP format: record['meta'] is a Hash with keys like 'synonyms', 'country', etc.
    meta = record['meta'] || {}
    aliases = extract_aliases(record, display_name)
    # Also extract from meta.synonyms for MISP format
    if meta['synonyms'] && !aliases.any?
      aliases = normalize_string_array(meta['synonyms'])
    end
    aliases.reject! { |value| @overrides[:alias_drop_list].include?(normalize_key(value)) }
    country = resolve_country(record, canonical)
    # Also check meta.country for MISP format
    country = meta['country'] if country.to_s.empty? && meta['country']

    source_record_id = first_non_empty(record['id'], record['uuid'], record['group_id'], canonical) || canonical
    source_record_url = first_non_empty(record['url'], record['reference'], record['card_url'], meta['url'])
    # Also use description from meta for MISP format
    desc_from_meta = meta['description'] || meta['detail'] || meta['summary']
    description = sanitize_text(first_non_empty(record['description'], record['detail'], record['summary'], record['about'], desc_from_meta))
    description = "#{display_name} is tracked in ETDA/ThaiCERT threat group card data." if description.empty?
    first_seen = extract_year(first_non_empty(record['first_seen'], record['firstseen'], record['firstSeen'], meta['first_seen']))
    last_activity = extract_year(first_non_empty(record['last_activity'], record['lastseen'], record['updated'], record['last_seen'], meta['last_activity']))
    # Extract MITRE IDs from record fields and meta fields (MISP format)
    combined_record = record.dup
    meta.each { |k, v| combined_record[k] = v } if meta.is_a?(Hash)
    mitre_group_ids = extract_ids(combined_record, /G\d{4}/i)
    mitre_technique_ids = extract_ids(combined_record, /T\d{4}(?:\.\d{3})?/i)

    {
      raw_name: raw_name,
      display_name: display_name,
      canonical_key: canonical,
      aliases: aliases,
      description: description,
      url: "/#{slugify(display_name)}",
      country: country,
      sector_focus: normalize_string_array(first_non_empty(record['sector_focus'], record['sectors'], record['targeted_sectors'], record['targets'])),
      operations: normalize_string_array(first_non_empty(record['operations'], record['campaigns'], record['notable_campaigns'])),
      malware: normalize_string_array(first_non_empty(record['malware'], record['tools'], record['toolset'])),
      first_seen: first_seen,
      last_activity: last_activity,
      source_record_id: source_record_id.to_s,
      source_record_url: sanitize_url(source_record_url),
      source_dataset_url: @options[:source_url],
      source_retrieved_at: Time.now.utc.iso8601,
      mitre_group_ids: mitre_group_ids,
      mitre_technique_ids: mitre_technique_ids,
      source_transforms: [
        'normalized-name',
        'deduplicated-aliases',
        'normalized-optional-fields',
        'adapted-for-threatactor-info'
      ]
    }
  end

  def extract_aliases(record, display_name)
    sources = [
      record['aliases'],
      record['alias'],
      record['other_names'],
      record['synonyms'],
      record[:aliases],
      record[:alias],
      record[:other_names],
      record[:synonyms]
    ]
    values = sources.flat_map { |value| normalize_string_array(value) }
    values.reject { |value| normalize_key(value) == normalize_key(display_name) }.uniq.sort
  end

  def resolve_country(record, canonical_key)
    override = @overrides[:country_overrides][canonical_key]
    return override unless override.to_s.empty?

    sanitize_text(first_non_empty(record['country'], record['origin_country'], record['state_sponsor'], record[:country], record[:origin_country], record[:state_sponsor]))
  end

  def extract_ids(record, regex)
    text = record.values.flatten.compact.map(&:to_s).join(' ')
    text.scan(regex).map(&:upcase).uniq.sort
  end

  def normalize_string_array(value)
    case value
    when nil
      []
    when Array
      value.flat_map { |entry| normalize_string_array(entry) }
    when Hash
      value.values.flat_map { |entry| normalize_string_array(entry) }
    else
      value.to_s.split(/[,;\n]/).map { |entry| sanitize_text(entry) }.reject(&:empty?)
    end
  end

  def first_non_empty(*values)
    values.find do |value|
      next false if value.nil?

      if value.is_a?(Array) || value.is_a?(Hash)
        !normalize_string_array(value).empty?
      else
        !sanitize_text(value).empty?
      end
    end
  end

  def load_overrides
    return unless File.exist?(@options[:overrides_file])

    payload = safe_load_yaml_file(@options[:overrides_file]) || {}
    @overrides[:excluded_group_keys] = Array(payload['excluded_group_keys']).map { |value| normalize_key(value) }.reject(&:empty?).uniq
    @overrides[:match_overrides] = normalize_override_hash(payload['match_overrides'], preserve_values: true)
    @overrides[:display_name_overrides] = normalize_override_hash(payload['display_name_overrides'], preserve_values: true)
    @overrides[:country_overrides] = normalize_override_hash(payload['country_overrides'], preserve_values: true)
    @overrides[:alias_drop_list] = Array(payload['alias_drop_list']).map { |value| normalize_key(value) }.reject(&:empty?).uniq
  end

  def normalize_override_hash(value, preserve_values: false)
    (value || {}).each_with_object({}) do |(key, mapped_value), memo|
      normalized_key = normalize_key(key)
      next if normalized_key.empty?

      memo[normalized_key] = preserve_values ? mapped_value : normalize_key(mapped_value)
    end
  end

  def normalize_key(value)
    sanitize_text(value).downcase.tr('0$@', 'osa').gsub(/[^a-z0-9]/, '')
  end

  def slugify(value)
    sanitize_text(value).downcase.tr('0$@', 'osa').gsub(/[^a-z0-9]+/, '-').gsub(/\A-|-\z/, '').gsub(/-+/, '-')
  end

  def sanitize_text(value)
    value.to_s
         .gsub(/<br\s*\/?>/i, ' ')
         .gsub(/<[^>]+>/, ' ')
         .gsub(/&quot;/, '"')
         .gsub(/&#39;/, "'")
         .gsub(/&amp;/, '&')
         .gsub(/\s+/, ' ')
         .strip
  end

  def sanitize_url(value)
    text = sanitize_text(value)
    return nil unless text.match?(%r{\Ahttps?://}i)

    text
  end

  def extract_year(value)
    match = sanitize_text(value).match(/(19|20)\d{2}/)
    match && match[0]
  end

  def http_get(url, limit = 5)
    raise "Too many redirects for #{url}" if limit <= 0

    uri = URI.parse(url)
    response = Net::HTTP.get_response(uri)
    case response
    when Net::HTTPSuccess
      parse_response_body(response.body)
    when Net::HTTPRedirection
      location = response['location']
      raise "Redirect without location for #{url}" if location.to_s.empty?

      http_get(location, limit - 1)
    else
      raise "HTTP #{response.code} for #{url}"
    end
  end

  def parse_response_body(body)
    JSON.parse(body)
  rescue JSON::ParserError
    rows = CSV.parse(body, headers: true)
    rows.map(&:to_h)
  end

  def safe_load_yaml_file(path)
    YAML.safe_load(File.read(path), permitted_classes: [], aliases: true)
  end

  def deep_dup_hash(value)
    JSON.parse(JSON.generate(value))
  end

  def write_page(path, front_matter, body)
    FileUtils.mkdir_p(File.dirname(path))
    content = []
    content << '---'
    front_matter.each do |key, value|
      next if value.nil? || value == ''

      content << if value.is_a?(Array)
                   "#{key}: #{value.map(&:to_s).uniq.to_json}"
                 else
                   "#{key}: #{value.to_json}"
                 end
    end
    content << '---'
    content << ''
    content << body.strip
    content << ''
    File.write(path, content.join("\n"))
  end

  def load_pages
    Dir.glob(File.join(PAGE_DIR, '*.md')).each_with_object({}) do |path, pages|
      pages[path] = parse_page(path)
    end
  end

  def parse_page(path)
    content = File.read(path)
    match = content.match(/\A---\s*\n(.*?)\n---\s*\n?(.*)\z/m)
    raise "Invalid front matter in #{path}" unless match

    {
      front_matter: YAML.safe_load(match[1], permitted_classes: [], aliases: true) || {},
      body: match[2].strip
    }
  end

  def page_path_for(url)
    File.join(PAGE_DIR, "#{url.sub(%r{^/}, '')}.md")
  end
end

EtdaThaicertImporter.new(ARGV).run if __FILE__ == $PROGRAM_NAME
