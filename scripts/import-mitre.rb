#!/usr/bin/env ruby
# frozen_string_literal: true

# MITRE ATT&CK STIX 2.1 importer (fetch / plan / import)
# Source: https://github.com/mitre-attack/attack-stix-data

require 'fileutils'
require 'json'
require 'net/http'
require 'optparse'
require 'time'
require 'uri'
require 'yaml'

require_relative 'actor_store'
require_relative 'import_utils'
require_relative 'mitre/mitre_common'
require_relative 'mitre/stix_loader'
require_relative 'mitre/relationship_resolver'
require_relative 'mitre/entity_writers'

class MitreAttackImporter
  DEFAULT_SNAPSHOT_ROOT = 'data/imports/mitre-attack'.freeze
  THREAT_ACTORS_DIR = '_threat_actors'.freeze
  SOURCE_NAME = 'MITRE ATT&CK'.freeze

  def initialize(argv)
    @argv = argv.dup
    @command = @argv.shift
    @options = {
      output: nil,
      snapshot: nil,
      domains: %w[enterprise mobile ics],
      version: nil,
      skip_revoked: true,
      new_only: false,
      force: false,
      write: false,
      report_json: nil,
      verbose: false
    }
  end

  def run
    case @command
    when 'fetch'
      parse_fetch_options
      fetch_snapshot
    when 'plan'
      parse_import_options
      plan_snapshot
    when 'import'
      parse_import_options
      @options[:write] = true
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
        ruby scripts/import-mitre.rb fetch --output DIR [--domain enterprise] [--domain mobile] [--domain ics] [--version X.Y]
        ruby scripts/import-mitre.rb plan --snapshot DIR [--report-json PATH]
        ruby scripts/import-mitre.rb import --snapshot DIR [--report-json PATH] [--new-only] [--force]

      Source: https://github.com/mitre-attack/attack-stix-data
    TEXT
  end

  def parse_fetch_options
    @options[:domains] = []
    parser = OptionParser.new do |opts|
      opts.banner = 'Usage: ruby scripts/import-mitre.rb fetch [options]'
      opts.on('--output DIR', 'Snapshot directory') { |v| @options[:output] = v }
      opts.on('--domain NAME', 'enterprise | mobile | ics (repeatable)') { |v| @options[:domains] << v }
      opts.on('--version VER', 'Pin ATT&CK version (e.g. 19.0); uses versioned JSON filenames') { |v| @options[:version] = v }
    end
    parser.parse!(@argv)
    @options[:output] ||= File.join(DEFAULT_SNAPSHOT_ROOT, Time.now.utc.strftime('%Y-%m-%d'))
    @options[:domains] = %w[enterprise mobile ics] if @options[:domains].empty?
    @options[:domains].uniq!
  end

  def parse_import_options
    parser = OptionParser.new do |opts|
      opts.banner = 'Usage: ruby scripts/import-mitre.rb plan|import --snapshot DIR [options]'
      opts.on('--snapshot DIR', 'Snapshot directory containing manifest.yml') { |v| @options[:snapshot] = v }
      opts.on('--report-json PATH', 'Write JSON report') { |v| @options[:report_json] = v }
      opts.on('--include-revoked', 'Include revoked/deprecated objects') { @options[:skip_revoked] = false }
      opts.on('--new-only', 'Import only new actors; skip merges') { @options[:new_only] = true }
      opts.on('--force', 'Overwrite malware summaries/descriptions when merging MITRE software pages') { @options[:force] = true }
      opts.on('-v', '--verbose') { @options[:verbose] = true }
    end
    parser.parse!(@argv)
    abort 'Missing --snapshot' if @options[:snapshot].to_s.empty?
  end

  def fetch_snapshot
    FileUtils.mkdir_p(@options[:output])
    manifest = { 'retrieved_at' => Time.now.utc.iso8601, 'bundles' => {} }

    @options[:domains].each do |domain|
      filename = versioned_filename(domain, @options[:version])
      url = MitreCommon.bundle_url(domain)
      unless @options[:version].nil?
        folder = MitreCommon::DOMAIN_FILES[domain][:folder]
        url = "#{MitreCommon::RAW_BASE}/#{folder}/#{filename}"
      end

      path = File.join(@options[:output], filename)
      puts "Fetching #{domain}: #{url}"
      download(url, path)

      manifest['bundles'][domain] = {
        'url' => url,
        'filename' => filename
      }
    end

    File.write(File.join(@options[:output], 'manifest.yml'), YAML.dump(manifest))
    puts "Wrote #{File.join(@options[:output], 'manifest.yml')}"
  end

  def versioned_filename(domain, ver)
    base = MitreCommon::DOMAIN_FILES[domain][:file].sub(/\.json\z/, '')
    return "#{base}.json" if ver.nil?

    "#{base}-#{ver}.json"
  end

  def download(url, path)
    uri = URI.parse(url)
    Net::HTTP.start(uri.host, uri.port, use_ssl: uri.scheme == 'https') do |http|
      req = Net::HTTP::Get.new(uri)
      res = http.request(req)
      raise "HTTP #{res.code} for #{url}" unless res.is_a?(Net::HTTPSuccess)

      File.binwrite(path, res.body)
    end
  end

  def load_manifest_snapshot
    snap = @options[:snapshot]
    manifest_path = File.file?(snap) ? File.dirname(snap) : snap
    manifest_file = File.join(manifest_path, 'manifest.yml')
    abort "Missing #{manifest_file}" unless File.exist?(manifest_file)

    manifest = YAML.safe_load(File.read(manifest_file), permitted_classes: [Time, Date], aliases: true) || {}
    bundle_paths = {}
    (manifest['bundles'] || {}).each do |domain, info|
      fn = info['filename']
      p = File.join(manifest_path, fn)
      bundle_paths[domain] = p if File.exist?(p)
    end
    [manifest_path, manifest, bundle_paths]
  end

  def plan_snapshot
    manifest_path, manifest, bundle_paths = load_manifest_snapshot
    puts 'Loading STIX bundles...'
    data = MitreStixLoader.load_and_merge(bundle_paths)
    resolver = MitreRelationshipResolver.new(data[:objects], data[:relationships], data[:domains_by_id])

    existing = ActorStore.load_all
    alias_index = ImportUtils.build_alias_index(existing)
    group_slug_map = build_group_slug_map(resolver, existing, alias_index, {})

    stats = build_plan_stats(resolver, existing, alias_index, group_slug_map)

    puts JSON.pretty_generate(stats) if @options[:verbose]

    puts "\n[PLAN] intrusion_sets: #{stats['intrusion_sets']}"
    puts "[PLAN] actors_merge: #{stats['actors_merge']}"
    puts "[PLAN] actors_create: #{stats['actors_create']}"
    puts "[PLAN] actors_review: #{stats['actors_review']}"
    puts "[PLAN] techniques: #{stats['techniques']}"
    puts "[PLAN] tactics: #{stats['tactics']}"
    puts "[PLAN] campaigns: #{stats['campaigns']}"
    puts "[PLAN] mitigations: #{stats['mitigations']}"
    puts "[PLAN] software: #{stats['software']}"

    write_report(stats.merge('mode' => 'plan', 'snapshot' => manifest_path))

    puts "\nRun: ruby scripts/import-mitre.rb import --snapshot #{manifest_path}"
  end

  def build_plan_stats(resolver, existing, alias_index, _group_slug_map)
    intrusion_sets = resolver.intrusion_sets
    merge_n = create_n = review_n = 0

    intrusion_sets.each do |is|
      actor = parse_intrusion_actor(is)
      next if actor.nil?

      m = ImportUtils.find_match(actor['name'], actor['aliases'], alias_index)
      if m && m[:confidence] == :high
        merge_n += 1
      elsif m && m[:confidence] == :ambiguous
        review_n += 1
      else
        create_n += 1
      end
    end

    {
      'intrusion_sets' => intrusion_sets.size,
      'actors_merge' => merge_n,
      'actors_create' => create_n,
      'actors_review' => review_n,
      'techniques' => resolver.technique_objects.size,
      'tactics' => resolver.tactic_objects.size,
      'campaigns' => resolver.campaign_objects.size,
      'mitigations' => resolver.mitigation_objects.size,
      'software' => resolver.software_objects.size
    }
  end

  def import_snapshot
    manifest_path, manifest, bundle_paths = load_manifest_snapshot
    puts 'Loading STIX bundles...'
    data = MitreStixLoader.load_and_merge(bundle_paths)
    resolver = MitreRelationshipResolver.new(data[:objects], data[:relationships], data[:domains_by_id])

    dataset_urls = {}
    (manifest['bundles'] || {}).each do |domain, info|
      dataset_urls[domain] = info['url']
    end

    existing_actors = ActorStore.load_all
    alias_index = ImportUtils.build_alias_index(existing_actors)

    opts_actor = { skip_revoked: @options[:skip_revoked] }
    group_slug_map = build_group_slug_map(resolver, existing_actors, alias_index, opts_actor)

    puts 'Writing MITRE entity pages...'
    writers = MitreEntityWriters.new(resolver, data[:domains_by_id], group_slug_map: group_slug_map,
                                                                      skip_revoked: @options[:skip_revoked])
    wt = writers.write_techniques!
    wta = writers.write_tactics!
    wc = writers.write_campaigns!
    wm = writers.write_mitigations!
    ws = writers.write_software!(force_description: @options[:force])
    puts "  techniques=#{wt} tactics=#{wta} campaigns=#{wc} mitigations=#{wm} software=#{ws}"

    results = { merge: [], create: [], skip: [], review: [] }

    resolver.intrusion_sets.each do |is|
      incoming = parse_intrusion_actor(is, opts_actor)
      next if incoming.nil?

      stix_id = is['id']
      incoming = enrich_actor_from_intrusion(incoming, stix_id, resolver)
      incoming['provenance']['mitre']['source_dataset_urls'] = dataset_urls

      match = ImportUtils.find_match(incoming['name'], incoming['aliases'], alias_index)

      if match && match[:confidence] == :high
        next if @options[:new_only]

        existing = existing_actors[match[:position]]
        merged = ImportUtils.merge_actors(existing, incoming, 'MITRE', dataset_urls)
        existing_actors[match[:position]] = merged
        results[:merge] << { name: incoming['name'], mitre_id: incoming['mitre_id'] }
      elsif match && match[:confidence] == :ambiguous
        results[:review] << { name: incoming['name'], candidates: match[:positions].map { |i| existing_actors[i]['name'] } }
      else
        existing_actors << incoming
        results[:create] << incoming
        alias_index = ImportUtils.build_alias_index(existing_actors)
      end
    end

    puts "\nWriting _data/actors/*.yml..."
    ActorStore.save_all(existing_actors)

    ref_cache = {}
    existing_actors.each do |actor|
      name = actor['name']
      next unless name

      refs = actor.delete('references') || []
      ref_cache[name] = refs if refs.any?
    end
    File.write('_data/references.json', JSON.pretty_generate(ref_cache))
    puts "Saved #{ref_cache.size} actor reference sets to _data/references.json"

    existing_actors.each do |actor|
      actor['references'] = ref_cache[actor['name']] if ref_cache[actor['name']]
    end

    FileUtils.mkdir_p(THREAT_ACTORS_DIR)
    results[:create].each do |actor|
      write_new_actor_page(actor)
    end

    stats = {
      'mode' => 'import',
      'snapshot' => manifest_path,
      'merged' => results[:merge].size,
      'created_actors' => results[:create].size,
      'review' => results[:review].size,
      'entity_pages' => { 'techniques' => wt, 'tactics' => wta, 'campaigns' => wc, 'mitigations' => wm, 'software' => ws }
    }
    write_report(stats)

    puts "\n✓ Import complete. Run: ruby scripts/validate-content.rb"
  end

  def build_group_slug_map(resolver, existing_actors, alias_index, opts_actor)
    map = {}
    resolver.intrusion_sets.each do |is|
      actor = parse_intrusion_actor(is, opts_actor)
      next if actor.nil?

      stix_id = is['id']
      match = ImportUtils.find_match(actor['name'], actor['aliases'], alias_index)
      url = if match && match[:confidence] == :high
              existing_actors[match[:position]]['url']
            else
              actor['url']
            end
      map[stix_id] = { 'name' => actor['name'], 'url' => url }
    end
    map
  end

  def enrich_actor_from_intrusion(actor, stix_id, resolver)
    actor['ttps'] = resolver.group_uses_techniques(stix_id)
    actor['software'] = resolver.group_uses_software(stix_id)
    actor['campaigns'] = resolver.campaigns_for_group(stix_id)
    actor['provenance'] ||= {}
    actor['provenance']['mitre'] ||= {}
    actor['provenance']['mitre']['stix_intrusion_set_id'] = stix_id
    actor['provenance']['mitre']['relationships_imported_at'] = Time.now.utc.iso8601
    actor
  end

  def parse_intrusion_actor(intrusion_set, opts = {})
    skip_revoked = opts.fetch(:skip_revoked, true)
    name = intrusion_set['name']
    return nil if name.nil? || name.empty?

    if skip_revoked
      return nil if intrusion_set['revoked'] == true
      return nil if intrusion_set['x_mitre_deprecated'] == true
    end

    external_id = nil
    mitre_url = nil
    references = []

    (intrusion_set['external_references'] || []).each do |ref|
      source = ref['source_name'] || ref['source'] || 'unknown'
      raw_url = ref['url'] || ''
      url = clean_ref_url(raw_url)

      references << {
        'source' => source,
        'url' => url,
        'description' => clean_ref_description(ref['description'])
      }

      if source == 'mitre-attack'
        external_id = ref['external_id']
        mitre_url = ref['url']
      end
    end

    url_slug = MitreCommon.slugify_group(external_id, name)

    {
      'name' => name,
      'aliases' => intrusion_set['aliases'] || [],
      'description' => MitreCommon.clean_description(intrusion_set['description']),
      'url' => "/#{url_slug}/",
      'external_id' => external_id,
      'mitre_id' => external_id,
      'external_url' => mitre_url,
      'mitre_url' => mitre_url,
      'references' => references,
      'source' => SOURCE_NAME,
      'source_attribution' => MitreCommon::SOURCE_ATTRIBUTION,
      'provenance' => {
        'mitre' => {
          'source_retrieved_at' => Time.now.utc.iso8601,
          'source_record_id' => external_id || name,
          'source_dataset_url' => MitreCommon.bundle_url('enterprise')
        }
      }
    }
  end

  def clean_ref_description(desc)
    return nil if desc.nil? || desc.empty?

    desc.length > 500 ? "#{desc[0..496]}..." : desc
  end

  def clean_ref_url(url)
    return nil if url.nil? || url.empty?

    if url.include?('pdf') || url.include?('#zoom')
      base = url.split('#').first.split('?').first
      return base if base.length < url.length && base.length > 20
    end

    if url.length > 200
      uri = URI.parse(url)
      short = "#{uri.scheme}://#{uri.host}#{uri.path[%r{^/[^/]{1,30}}]}"
      return "#{short}..." if short.length < url.length - 50
    end

    url
  end

  def write_new_actor_page(actor)
    url = actor['url'].gsub(%r{^/|/$}, '')
    filename = File.join(THREAT_ACTORS_DIR, "#{url}.md")
    yaml_lines = []
    yaml_lines << 'layout: threat_actor'
    yaml_lines << "title: \"#{actor['name']}\""
    aliases_str = actor['aliases'].map { |a| "\"#{a}\"" }.join(', ')
    yaml_lines << "aliases: [#{aliases_str}]"
    yaml_lines << "description: \"#{actor['description'][0..200].gsub('"', '\\\\"')}\""
    yaml_lines << "permalink: #{actor['url']}"
    yaml_lines << "external_id: #{actor['external_id']}"
    yaml_lines << "source_attribution: \"#{actor['source_attribution'].gsub('"', '\\\\"')}\""

    content = <<~CONTENT
      ---
      #{yaml_lines.join("\n")}
      ---

      ## Introduction
      #{actor['description']}

      ## Activities and Tactics
      *Information pending cataloguing.*

      ### Notable Campaigns
      *Information pending cataloguing.*

      ### Tactics, Techniques, and Procedures (TTPs)
      *Information pending cataloguing.*

      ## Notable Indicators of Compromise (IOCs)
      *This section is pending cataloguing. Check upstream sources for current IOCs.*

      ### IP Addresses
      *Pending*

      ### File Hashes
      *Pending*

      ### Domains
      *Pending*

      ### URLs
      *Pending*

      ## Malware and Tools
      *Information pending cataloguing.*

      ## Attribution and Evidence
      #{actor['source_attribution']}

      ### Attribution
      *Information pending cataloguing.*

      ## References
      - [MITRE ATT&CK - #{actor['name']}](#{actor['mitre_url']})
    CONTENT

    File.write(filename, content)
    puts "  [CREATE] #{filename}"
  end

  def write_report(payload)
    path = @options[:report_json]
    return if path.to_s.empty?

    FileUtils.mkdir_p(File.dirname(path))
    File.write(path, JSON.pretty_generate(payload))
    puts "Wrote report #{path}"
  end
end

MitreAttackImporter.new(ARGV).run if __FILE__ == $PROGRAM_NAME
