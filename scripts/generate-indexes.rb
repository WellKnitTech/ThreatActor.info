#!/usr/bin/env ruby

require 'json'
require 'yaml'
require 'fileutils'
require 'set'
require 'time'
require 'uri'
require 'net/http'
require_relative 'actor_store'
require_relative 'mitre/stix_loader'
require_relative 'mitre/relationship_resolver'
require_relative 'mitre/mitre_common'

class ThreatActorIndexGenerator
  PAGES_GLOB = '_threat_actors/*.md'.freeze
  OUTPUT_DIR = '_data/generated'.freeze
  API_DIR = 'api'.freeze
  MALWARE_DIR = '_malware'.freeze
  TACTICS_DIR = '_tactics'.freeze
  # Cached Enterprise bundle for full ATT&CK indexes when no importer snapshot exists (gitignored).
  ENTERPRISE_BUNDLE_CACHE = 'data/mitre-cache/enterprise-attack.json'.freeze
  TYPE_SHARDS_DIR = File.join(OUTPUT_DIR, 'iocs_by_type').freeze
  API_TYPE_SHARDS_DIR = File.join(API_DIR, 'iocs', 'by-type').freeze
  REQUIRED_IOC_HEADING = 'Notable Indicators of Compromise (IOCs)'.freeze
  SKIPPED_IOC_HEADINGS = ['Sources'].freeze
  IPV4_PATTERN = /\b(?:\d{1,3}\.){3}\d{1,3}\b/.freeze
  DOMAIN_PATTERN = /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,63}|onion)\b/i.freeze
  EMAIL_PATTERN = /\b[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,63}\b/i.freeze
  URL_PATTERN = %r{\b(?:https?|ftp)://[^\s<>()]+}i.freeze
  FILE_EXTENSION_PATTERN = /\.[a-z0-9]{2,12}\b/i.freeze
  FILENAME_PATTERN = /\b[\w.-]+\.[A-Za-z0-9]{2,12}\b/.freeze
  CVE_PATTERN = /\bCVE-\d{4}-\d{4,7}\b/i.freeze
  ATTACK_TECHNIQUE_PATTERN = /\bT\d{4}(?:\.\d{3})?\b/i.freeze

  # Embedded Enterprise ATT&CK tactics when no `_tactics/` pages and no imported snapshot exists.
  ENTERPRISE_TACTICS_FALLBACK = [
    %w[TA0043 Reconnaissance reconnaissance],
    %w[TA0042 Resource-Development resource-development],
    %w[TA0001 Initial-Access initial-access],
    %w[TA0002 Execution execution],
    %w[TA0003 Persistence persistence],
    %w[TA0004 Privilege-Escalation privilege-escalation],
    %w[TA0005 Defense-Evasion defense-evasion],
    %w[TA0006 Credential-Access credential-access],
    %w[TA0007 Discovery discovery],
    %w[TA0008 Lateral-Movement lateral-movement],
    %w[TA0009 Collection collection],
    %w[TA0011 Command-and-Control command-and-control],
    %w[TA0010 Exfiltration exfiltration],
    %w[TA0040 Impact impact]
  ].freeze

  # Display metadata, URL slugs (under /iocs/<slug>/), category (hub sections), and default grouping.
  IOC_TYPE_DISPLAY = {
    'ip_address' => {
      label: 'IP Addresses',
      description: 'IPv4 indicators grouped by /16 network prefix.',
      category: 'network',
      page_slug: 'ip-address',
      grouping: 'cidr16'
    },
    'domain' => {
      label: 'Domains',
      description: 'Hostname indicators grouped by registrable domain (last two labels).',
      category: 'network',
      page_slug: 'domain',
      grouping: 'etld1'
    },
    'url' => {
      label: 'URLs',
      description: 'Full URLs grouped by scheme and site (registrable host).',
      category: 'network',
      page_slug: 'url',
      grouping: 'url_host'
    },
    'email' => {
      label: 'Email addresses',
      description: 'Address indicators grouped by domain part.',
      category: 'host',
      page_slug: 'email',
      grouping: 'email_domain'
    },
    'md5' => {
      label: 'MD5 hashes',
      description: 'File hash indicators (MD5), grouped by threat actor.',
      category: 'hash',
      page_slug: 'md5',
      grouping: 'by_actor'
    },
    'sha1' => {
      label: 'SHA-1 hashes',
      description: 'File hash indicators (SHA-1), grouped by threat actor.',
      category: 'hash',
      page_slug: 'sha1',
      grouping: 'by_actor'
    },
    'sha256' => {
      label: 'SHA-256 hashes',
      description: 'File hash indicators (SHA-256), grouped by threat actor.',
      category: 'hash',
      page_slug: 'sha256',
      grouping: 'by_actor'
    },
    'cve' => {
      label: 'CVEs',
      description: 'Vulnerability references grouped by publication year.',
      category: 'vuln',
      page_slug: 'cve',
      grouping: 'cve_year'
    },
    'attack_technique' => {
      label: 'ATT&CK techniques',
      description: 'Technique references grouped by parent technique ID (T####).',
      category: 'attack',
      page_slug: 'attack-technique',
      grouping: 'technique_parent'
    },
    'file_extension' => {
      label: 'File extensions',
      description: 'Extension indicators grouped by first character.',
      category: 'host',
      page_slug: 'file-extension',
      grouping: 'first_letter'
    },
    'filename' => {
      label: 'Filenames',
      description: 'Filename indicators grouped by first character.',
      category: 'host',
      page_slug: 'filename',
      grouping: 'first_letter'
    }
  }.freeze

  def initialize
    @actors = load_actors
    @pages = load_pages
    @mitre_counts = {}
  end

  def run
    FileUtils.mkdir_p(OUTPUT_DIR)
    FileUtils.mkdir_p(TYPE_SHARDS_DIR)
    FileUtils.mkdir_p(API_DIR)
    FileUtils.mkdir_p(API_TYPE_SHARDS_DIR)

    actor_documents = []
    ioc_documents = []
    campaign_documents = []
    malware_documents = []
    attack_mapping_documents = []
    reference_documents = []

    @actors.each do |actor|
      page_path = page_path_for(actor['url'])
      page = @pages[page_path]
      next unless page

      body = page[:body]
      ioc_section = extract_section(body, REQUIRED_IOC_HEADING)
      actor_iocs = extract_iocs(actor, page, ioc_section)
      campaigns = extract_campaigns(actor, page, body)
      malware_entries = extract_malware_and_tools(actor, page, body)
      attack_mappings = extract_attack_mappings(actor, page, body)
      references = extract_references(actor, page, body, ioc_section)

      actor_documents << build_actor_document(actor, page, actor_iocs, body, campaigns, malware_entries, attack_mappings, references)
      ioc_documents.concat(actor_iocs)
      campaign_documents.concat(campaigns)
      malware_documents.concat(malware_entries)
      attack_mapping_documents.concat(flatten_attack_mappings(actor, page, attack_mappings))
      reference_documents.concat(references)
    end

    mitre_resolver = resolve_mitre_resolver_for_indexes
    technique_tactics_map = mitre_resolver ? build_technique_tactics_map(mitre_resolver) : {}

    technique_documents = build_mitre_collection_index('_techniques')
    if technique_documents.empty? && mitre_resolver
      technique_documents = build_techniques_from_resolver(mitre_resolver)
    elsif technique_documents.empty?
      technique_documents = build_technique_index_from_actor_yaml(@actors)
    end

    tactic_documents = build_mitre_collection_index('_tactics')
    if tactic_documents.empty? && mitre_resolver
      tactic_documents = build_tactics_documents_from_resolver(mitre_resolver)
    elsif tactic_documents.empty?
      tactic_documents = build_fallback_enterprise_tactics_documents
    end

    ensure_tactic_collection_pages(tactic_documents)

    campaign_mitre_documents = build_mitre_collection_index('_campaigns')
    mitigation_documents = build_mitre_collection_index('_mitigations')

    @mitre_counts = {
      techniques: technique_documents.length,
      tactics: tactic_documents.length,
      campaigns: campaign_mitre_documents.length,
      mitigations: mitigation_documents.length
    }

    actors_by_technique = build_actors_by_technique(actor_documents)
    actors_by_tactic = build_actors_by_tactic(actor_documents, technique_tactics_map)
    software_by_actor = build_software_by_actor(actor_documents)

    ioc_lookup = build_ioc_lookup(ioc_documents)
    ioc_type_manifest = build_ioc_type_manifest(ioc_documents)
    ioc_summary = build_ioc_summary(ioc_documents, ioc_type_manifest)

    write_json('threat_actors.json', actor_documents)
    write_json('recently_updated.json', build_recently_updated(actor_documents))
    write_json('iocs.json', ioc_documents)

    # Build facets with malware counts
    facets = build_facets(actor_documents, ioc_documents)
    facets[:malware_counts] = build_malware_counts(malware_documents)
    write_json('facets.json', facets)

    write_json('campaigns.json', campaign_documents)
    write_json('malware.json', malware_documents)
    write_json('attack_mappings.json', attack_mapping_documents)
    write_json('references.json', reference_documents)
    write_json('techniques.json', technique_documents)
    write_json('tactics.json', tactic_documents)
    write_json('mitigations.json', mitigation_documents)
    write_json('campaigns_mitre.json', campaign_mitre_documents)
    write_json('actors_by_technique.json', actors_by_technique)
    write_json('actors_by_tactic.json', actors_by_tactic)
    write_json('technique_tactics.json', technique_tactics_map)
    write_json('software_by_actor.json', software_by_actor)
    search_payload = build_search_index(actor_documents, technique_documents, campaign_mitre_documents)
    write_json('search_index.json', search_payload)
    write_json('ioc_lookup.json', ioc_lookup)
    write_json('ioc_types.json', ioc_type_manifest)
    write_json('ioc_summary.json', ioc_summary)
    write_ioc_type_shards(ioc_documents)
    
    # Generate malware pages from extracted data
    write_malware_pages(malware_documents, actor_documents)
    # Primary API endpoints are rendered via Liquid wrappers in /api.
    # Keep writing type shards directly because they are data-heavy static payloads.

    puts "Generated #{actor_documents.length} threat actors and #{ioc_documents.length} IOC records in #{OUTPUT_DIR}"
  end

  private

  def load_actors
    ActorStore.load_all
  end

  def load_pages
    Dir.glob(PAGES_GLOB).sort.each_with_object({}) do |path, pages|
      pages[path] = parse_page(path)
    end
  end

  def parse_page(path)
    content = File.read(path)
    match = content.match(/\A---\s*\n(.*?)\n---\s*\n?(.*)\z/m)
    raise "Invalid front matter in #{path}" unless match

    {
      path: path,
      front_matter: safe_load_yaml(match[1]) || {},
      body: match[2]
    }
  end

  def page_path_for(url)
    "_threat_actors#{url}.md"
  end

  def extract_section(body, heading)
    pattern = /^##\s+#{Regexp.escape(heading)}\s*$\n?(.*?)(?=^##\s+|\z)/m
    match = body.match(pattern)
    match ? match[1].strip : ''
  end

  def extract_iocs(actor, page, section)
    return [] if section.empty?

    current_heading = 'General'
    records = []
    seen = {}

    section.each_line do |line|
      stripped = line.strip
      next if stripped.empty?

      if stripped.start_with?('### ')
        current_heading = stripped.sub(/^###\s+/, '').strip
        next
      end

      next unless stripped.match?(/^[-*]\s+/)
      next if SKIPPED_IOC_HEADINGS.include?(current_heading)

      build_ioc_records(actor, page, current_heading, stripped).each do |record|
        key = [record[:actor_slug], record[:type], record[:normalized_value]].join('|')
        next if record[:normalized_value].empty? || seen[key]

        seen[key] = true
        records << record
      end
    end

    records
  end

  def build_ioc_records(actor, page, heading, line)
    content = line.sub(/^[-*]\s+/, '').strip
    candidates = extract_indicator_candidates(content, heading)

    if candidates.empty?
      [build_ioc_record(actor, page, heading, content, content, extract_label(content), nil, false)]
    else
      candidates.map do |candidate|
        build_ioc_record(actor, page, heading, candidate[:value], content, candidate[:label], candidate[:inferred_type], true)
      end
    end
  end

  def build_ioc_record(actor, page, heading, value, source_text, label, inferred_type, atomic)
    normalization = normalize_indicator(value, inferred_type)

    {
      actor_name: actor['name'],
      actor_slug: actor['url'].sub(%r{^/}, ''),
      actor_url: actor['url'],
      actor_permalink: page[:front_matter]['permalink'] || "#{actor['url']}/",
      type: ioc_type_for(heading),
      inferred_type: inferred_type,
      atomic: atomic,
      heading: heading,
      label: label,
      value: value.strip,
      normalized_value: normalization[:canonical_value],
      canonical_value: normalization[:canonical_value],
      legacy_normalized_value: normalization[:legacy_normalized_value],
      lookup_keys: atomic ? normalization[:lookup_keys] : [],
      source_text: strip_markdown(source_text),
      source_file: page[:path]
    }
  end

  def build_actor_document(actor, page, actor_iocs, body, campaigns, malware_entries, attack_mappings, references)
    front_matter = page[:front_matter]

    {
      name: actor['name'],
      aliases: actor['aliases'] || [],
      description: actor['description'],
      url: actor['url'],
      permalink: front_matter['permalink'] || "#{actor['url']}/",
      country: actor['country'],
      sector_focus: actor['sector_focus'] || [],
      first_seen: actor['first_seen'],
      last_activity: actor['last_activity'],
      last_updated: actor['last_updated'] || front_matter['last_updated'],
      risk_level: actor['risk_level'],
      source_name: actor['source_name'] || front_matter['source_name'],
      source_attribution: actor['source_attribution'] || front_matter['source_attribution'],
      source_record_url: actor['source_record_url'] || front_matter['source_record_url'],
      source_license: actor['source_license'] || front_matter['source_license'],
      source_license_url: actor['source_license_url'] || front_matter['source_license_url'],
      provenance: actor['provenance'] || {},
      page_path: page[:path],
      headings: extract_h2_headings(body),
      ioc_count: actor_iocs.length,
      ioc_types: actor_iocs.map { |ioc| ioc[:type] }.uniq.sort,
      campaigns: campaigns,
      malware_and_tools: malware_entries,
      attack_mappings: attack_mappings,
      references: references,
      campaign_count: campaigns.length,
      malware_count: malware_entries.length,
      reference_count: references.length,
      attack_mapping_count: attack_mappings.values.flatten.length,
      mitre_ttps: actor['ttps'] || [],
      mitre_software: actor['software'] || [],
      mitre_campaigns_yaml: actor['campaigns'] || []
    }
  end

  def build_facets(actors, iocs)
    # Precompute counts for sidebar
    country_counts = actors.each_with_object(Hash.new(0)) do |actor, counts|
      counts[actor[:country]] += 1 if actor[:country]
    end.sort_by { |_, count| -count }.first(10).to_h
    
    risk_counts = actors.each_with_object(Hash.new(0)) do |actor, counts|
      counts[actor[:risk_level]] += 1 if actor[:risk_level]
    end
    
    sector_counts = actors.each_with_object(Hash.new(0)) do |actor, counts|
      (actor[:sector_focus] || []).each do |sector|
        counts[sector] += 1
      end
    end.sort_by { |_, count| -count }.first(10).to_h
    
    {
      countries: unique_sorted(actors.map { |actor| actor[:country] }),
      risk_levels: risk_levels_in_order(actors.map { |actor| actor[:risk_level] }),
      sectors: unique_sorted(actors.flat_map { |actor| actor[:sector_focus] || [] }),
      ioc_types: unique_sorted(iocs.map { |ioc| ioc[:type] }),
      counts: {
        threat_actors: actors.length,
        iocs: iocs.length,
        techniques: (@mitre_counts&.dig(:techniques)) || 0,
        tactics: (@mitre_counts&.dig(:tactics)) || 0,
        campaigns_mitre: (@mitre_counts&.dig(:campaigns)) || 0,
        mitigations: (@mitre_counts&.dig(:mitigations)) || 0
      },
      # Precomputed counts for sidebar
      country_counts: country_counts,
      risk_counts: risk_counts,
      sector_counts: sector_counts
    }
  end

  def build_recently_updated(actors)
    actors
      .select { |actor| actor[:last_updated].to_s.match?(/\A\d{4}-\d{2}-\d{2}\z/) }
      .sort_by { |actor| actor[:last_updated] }
      .reverse
      .first(12)
      .map do |actor|
        {
          name: actor[:name],
          aliases: actor[:aliases],
          description: actor[:description],
          url: actor[:url],
          permalink: actor[:permalink],
          country: actor[:country],
          sector_focus: actor[:sector_focus],
          risk_level: actor[:risk_level],
          last_updated: actor[:last_updated],
          last_activity: actor[:last_activity],
          ioc_count: actor[:ioc_count]
        }
      end
  end
  
  # Add malware counts to facets (called from main)
  def build_malware_counts(malware_documents)
    malware_counts = malware_documents.each_with_object(Hash.new(0)) do |entry, counts|
      counts[entry[:name]] += 1 if entry[:name]
    end.sort_by { |_, count| -count }.first(10).to_h
    
    malware_counts
  end

  def build_ioc_lookup(iocs)
    iocs.each_with_object({}) do |ioc, lookup|
      next unless ioc[:atomic]

      ioc[:lookup_keys].each do |lookup_key|
        next if lookup_key.to_s.empty?

        entry = lookup[lookup_key] ||= {
          normalized_value: ioc[:canonical_value],
          types: [],
          inferred_types: [],
          actors: [],
          matches: []
        }

        entry[:types] << ioc[:type] unless entry[:types].include?(ioc[:type])
        if ioc[:inferred_type] && !entry[:inferred_types].include?(ioc[:inferred_type])
          entry[:inferred_types] << ioc[:inferred_type]
        end

        actor_reference = {
          name: ioc[:actor_name],
          slug: ioc[:actor_slug],
          permalink: ioc[:actor_permalink]
        }
        entry[:actors] << actor_reference unless entry[:actors].include?(actor_reference)
        entry[:matches] << ioc unless entry[:matches].include?(ioc)
      end
    end.sort.to_h
  end

  def build_ioc_type_manifest(iocs)
    grouped_iocs = iocs.group_by { |ioc| ioc[:type] }

    grouped_iocs.keys.sort.each_with_object({}) do |type, manifest|
      type_iocs = grouped_iocs[type]
      meta = ioc_type_metadata(type)
      manifest[type] = {
        type: type,
        label: meta[:label],
        description: meta[:description],
        category: meta[:category],
        page_url: ioc_type_page_url(type),
        top_actors: build_ioc_top_actors(type_iocs, 5),
        count: type_iocs.length,
        atomic_count: type_iocs.count { |ioc| ioc[:atomic] },
        unique_values: type_iocs.map { |ioc| ioc[:normalized_value] }.uniq.length,
        path: "/api/iocs/by-type/#{type}.json"
      }
    end
  end

  def build_ioc_summary(iocs, ioc_type_manifest)
    {
      total_records: iocs.length,
      total_unique_values: iocs.map { |ioc| ioc[:normalized_value] }.uniq.length,
      actor_count_with_iocs: iocs.map { |ioc| ioc[:actor_slug] }.uniq.length,
      type_count: ioc_type_manifest.keys.length
    }
  end

  def write_ioc_type_shards(iocs)
    clear_existing_shards(TYPE_SHARDS_DIR)
    clear_existing_shards(API_TYPE_SHARDS_DIR)

    iocs.group_by { |ioc| ioc[:type] }.each do |type, type_iocs|
      meta = ioc_type_metadata(type)
      grouping = meta[:grouping] || 'by_actor'
      groups = build_ioc_groups(type, type_iocs)
      facets = { actor: build_actor_facet_list(type_iocs) }

      sorted_records = type_iocs.sort_by do |ioc|
        [ioc[:normalized_value].to_s.downcase, ioc[:actor_slug].to_s]
      end

      payload = {
        type: type,
        label: meta[:label],
        description: meta[:description],
        category: meta[:category],
        page_url: ioc_type_page_url(type),
        count: type_iocs.length,
        atomic_count: type_iocs.count { |ioc| ioc[:atomic] },
        unique_values: type_iocs.map { |ioc| ioc[:normalized_value] }.uniq.length,
        grouping: grouping,
        groups: groups,
        facets: facets,
        records: sorted_records
      }

      write_json(File.join('iocs_by_type', "#{type}.json"), payload)
      write_api_json(File.join('iocs', 'by-type', "#{type}.json"), payload)
    end
  end

  def ioc_type_metadata(type)
    IOC_TYPE_DISPLAY[type] || default_ioc_type_metadata(type)
  end

  def default_ioc_type_metadata(type)
    {
      label: humanize_ioc_type(type),
      description: 'Indicators extracted under this IOC subsection heading.',
      category: 'other',
      page_slug: 'other',
      grouping: 'by_actor'
    }
  end

  def humanize_ioc_type(type)
    type.to_s.tr('_', ' ').split.map { |w| w.capitalize }.join(' ')
  end

  def ioc_type_page_url(type)
    meta = ioc_type_metadata(type)
    if IOC_TYPE_DISPLAY.key?(type)
      "/iocs/#{meta[:page_slug]}/"
    else
      "/iocs/other/?ioc_type=#{URI.encode_www_form_component(type)}"
    end
  end

  def build_ioc_top_actors(type_iocs, limit)
    counts = Hash.new(0)
    type_iocs.each { |ioc| counts[ioc[:actor_slug]] += 1 }

    counts.sort_by { |_, c| -c }.first(limit).map do |slug, count|
      ref = type_iocs.find { |i| i[:actor_slug] == slug }
      { name: ref[:actor_name], slug: slug, count: count }
    end
  end

  def build_actor_facet_list(type_iocs)
    counts = Hash.new(0)
    names = {}
    type_iocs.each do |ioc|
      slug = ioc[:actor_slug]
      counts[slug] += 1
      names[slug] ||= ioc[:actor_name]
    end

    counts.sort_by { |_, c| -c }.map do |slug, count|
      { name: names[slug], slug: slug, count: count }
    end
  end

  def build_ioc_groups(type, type_iocs)
    case type
    when 'ip_address'
      group_ioc_ip_cidr16(type_iocs)
    when 'domain'
      group_ioc_domain_etld1(type_iocs)
    when 'url'
      group_ioc_url_host(type_iocs)
    when 'email'
      group_ioc_email_domain(type_iocs)
    when 'md5', 'sha1', 'sha256'
      group_ioc_by_actor(type_iocs)
    when 'cve'
      group_ioc_cve_year(type_iocs)
    when 'attack_technique'
      group_ioc_technique_parent(type_iocs)
    when 'file_extension', 'filename'
      group_ioc_first_letter(type_iocs)
    else
      group_ioc_by_actor(type_iocs)
    end
  end

  def sort_groups(groups)
    groups.sort_by { |g| [-g[:count], g[:key].to_s.downcase] }
  end

  def group_ioc_ip_cidr16(type_iocs)
    buckets = Hash.new { |h, k| h[k] = [] }
    type_iocs.each do |ioc|
      val = ioc[:normalized_value].to_s
      octets = val.split('.')
      key = if octets.length >= 2 && octets.all? { |o| o.match?(/\A\d{1,3}\z/) }
              "#{octets[0]}.#{octets[1]}"
            else
              '_other'
            end
      buckets[key] << ioc
    end

    buckets.map do |key, recs|
      sorted = recs.sort_by { |i| i[:value].to_s.downcase }
      label = if key == '_other'
                'Non-IPv4 or malformed'
              else
                "#{key}.0.0/16"
              end
      { key: key, label: label, count: sorted.length, records: sorted }
    end.then { |g| sort_groups(g) }
  end

  def group_ioc_domain_etld1(type_iocs)
    buckets = Hash.new { |h, k| h[k] = [] }
    type_iocs.each do |ioc|
      raw = ioc[:normalized_value].to_s.downcase.sub(/\.$/, '')
      host = raw.split('/').first.split(':').first
      key = etld1_simple(host)
      buckets[key] << ioc
    end

    buckets.map do |key, recs|
      sorted = recs.sort_by { |i| i[:value].to_s.downcase }
      { key: key, label: key, count: sorted.length, records: sorted }
    end.then { |g| sort_groups(g) }
  end

  def etld1_simple(host)
    parts = host.to_s.downcase.sub(/\.$/, '').split('.')
    return host.to_s if parts.length < 2

    parts.last(2).join('.')
  end

  def group_ioc_url_host(type_iocs)
    buckets = Hash.new { |h, k| h[k] = [] }
    type_iocs.each do |ioc|
      url = ioc[:normalized_value].to_s
      key, label = url_group_key_label(url)
      buckets[key] << { ioc: ioc, group_label: label }
    end

    buckets.map do |key, items|
      label = items.first[:group_label]
      recs = items.map { |x| x[:ioc] }
      sorted = recs.sort_by { |i| i[:value].to_s.downcase }
      { key: key, label: label, count: sorted.length, records: sorted }
    end.then { |g| sort_groups(g) }
  end

  def url_group_key_label(url)
    uri = URI.parse(url)
    unless uri.respond_to?(:host) && uri.host && !uri.host.to_s.strip.empty?
      return ['_unparseable', 'Unparseable URL']
    end

    scheme = (uri.scheme || 'http').downcase
    site = etld1_simple(uri.host)
    key = "#{scheme}://#{site}"
    [key, key]
  rescue URI::InvalidURIError, ArgumentError
    ['_unparseable', 'Unparseable URL']
  end

  def group_ioc_email_domain(type_iocs)
    buckets = Hash.new { |h, k| h[k] = [] }
    type_iocs.each do |ioc|
      email = ioc[:normalized_value].to_s.downcase
      domain = email.split('@', 2)[1]
      key = domain.nil? || domain.empty? ? '_unknown' : domain.strip
      buckets[key] << ioc
    end

    buckets.map do |key, recs|
      sorted = recs.sort_by { |i| i[:value].to_s.downcase }
      label = key == '_unknown' ? 'Unknown domain' : key
      { key: key, label: label, count: sorted.length, records: sorted }
    end.then { |g| sort_groups(g) }
  end

  def group_ioc_by_actor(type_iocs)
    buckets = Hash.new { |h, k| h[k] = [] }
    type_iocs.each { |ioc| buckets[ioc[:actor_slug]] << ioc }

    buckets.map do |slug, recs|
      sorted = recs.sort_by { |i| i[:value].to_s.downcase }
      name = recs.first[:actor_name]
      { key: slug, label: name, count: sorted.length, records: sorted }
    end.then { |g| sort_groups(g) }
  end

  def group_ioc_cve_year(type_iocs)
    buckets = Hash.new { |h, k| h[k] = [] }
    type_iocs.each do |ioc|
      v = ioc[:normalized_value].to_s.upcase
      year = v[/\ACVE-(\d{4})-/i, 1] || '_unknown'
      buckets[year] << ioc
    end

    buckets.map do |year, recs|
      sorted = recs.sort_by { |i| i[:value].to_s.downcase }
      label = year == '_unknown' ? 'Unknown year' : "CVE-#{year}-*"
      { key: year, label: label, count: sorted.length, records: sorted }
    end.then { |g| sort_groups(g) }
  end

  def group_ioc_technique_parent(type_iocs)
    buckets = Hash.new { |h, k| h[k] = [] }
    type_iocs.each do |ioc|
      tid = ioc[:normalized_value].to_s.upcase
      key = if (m = tid.match(/\A(T\d{4})(?:\.\d{3})?\z/))
              m[1]
            else
              '_unknown'
            end
      buckets[key] << ioc
    end

    buckets.map do |key, recs|
      sorted = recs.sort_by { |i| i[:value].to_s.downcase }
      label = key == '_unknown' ? 'Unknown technique' : "#{key} (*)"
      { key: key, label: label, count: sorted.length, records: sorted }
    end.then { |g| sort_groups(g) }
  end

  def group_ioc_first_letter(type_iocs)
    buckets = Hash.new { |h, k| h[k] = [] }
    type_iocs.each do |ioc|
      v = ioc[:value].to_s.strip
      letter = if v.empty?
                 '_other'
               else
                 c = v[0].upcase
                 c.match?(/[A-Z0-9]/) ? c : '_sym'
               end
      buckets[letter] << ioc
    end

    buckets.map do |key, recs|
      sorted = recs.sort_by { |i| i[:value].to_s.downcase }
      label = case key
              when '_other' then 'Other'
              when '_sym' then 'Symbols / non-alphanumeric'
              else key
              end
      { key: key, label: label, count: sorted.length, records: sorted }
    end.then { |g| sort_groups(g) }
  end
  
  def write_malware_pages(malware_documents, actor_documents)
    FileUtils.mkdir_p(MALWARE_DIR)
    
    malware_by_slug = malware_documents.each_with_object({}) do |document, groups|
      name = document[:name].to_s.strip
      next if name.empty?

      slug = slugify(name)
      next if slug.empty?

      groups[slug] ||= { name: name, entries: [] }
      groups[slug][:entries] << document
    end
    
    actor_lookup = actor_documents.each_with_object({}) do |actor, lookup|
      lookup[actor[:name]] = actor
    end

    malware_by_slug.sort.each do |slug, group|
      name = group[:name]
      entries = group[:entries]
      actor_list = build_malware_actor_list(entries, actor_lookup)
      
      front_matter = {
        'layout' => 'malware',
        'title' => name,
        'category' => entries.first[:category],
        'actor_count' => actor_list.length,
        'permalink' => "/malware/#{slug}/",
        'actors' => actor_list.map { |actor| actor.reject { |_, value| value.nil? } }
      }

      lines = front_matter.to_yaml.lines.map(&:chomp)
      lines << "---"
      lines << ""
      lines << "## Overview"
      lines << ""
      lines << "This page lists all known threat actors that have been observed using **#{name}**."
      lines << ""
      lines << "## Threat Actors"
      lines << ""
      actor_list.each do |a|
        lines << "- [#{a['name']}](#{a['url']})#{a['country'] ? " (#{a['country']})" : ""}#{a['risk_level'] ? " - #{a['risk_level']}" : ""}"
      end
      page_file = File.join(MALWARE_DIR, "#{slug}.md")
      File.write(page_file, lines.join("\n"))

      data_content = {
        name: name,
        slug: slug,
        category: entries.first[:category],
        actor_count: actor_list.length,
        actors: actor_list
      }
      File.write(File.join(MALWARE_DIR, "#{slug}.data.json"), JSON.pretty_generate(data_content))
    end
    
    index_content = {
      malware: malware_by_slug.sort.map do |slug, group|
        entries = group[:entries]
        {
          name: group[:name],
          slug: slug,
          url: "/malware/#{slug}/",
          category: entries.first[:category],
          actor_count: build_malware_actor_list(entries, actor_lookup).length
        }
      end
    }
    File.write(File.join(OUTPUT_DIR, 'malware_index.json'), JSON.pretty_generate(index_content))
    
    puts "Generated #{malware_by_slug.length} malware pages in #{MALWARE_DIR}"
  end

  def build_malware_actor_list(entries, actor_lookup)
    actor_list = []
    seen_actors = Set.new

    entries.each do |entry|
      actor = actor_lookup[entry[:actor_name]]
      next unless actor
      next if seen_actors.include?(actor[:name])

      seen_actors << actor[:name]
      actor_list << {
        'name' => actor[:name],
        'url' => actor[:permalink],
        'country' => actor[:country],
        'risk_level' => actor[:risk_level]
      }
    end

    actor_list.sort_by { |actor| actor['name'].downcase }
  end

  def slugify(value)
    value.to_s.downcase.gsub(/[^a-z0-9]+/, '-').gsub(/^-|-$/, '')
  end

  def clear_existing_shards(directory)
    Dir.glob(File.join(directory, '*.json')).each do |path|
      File.delete(path)
    end
  end

  def extract_h2_headings(body)
    body.scan(/^##\s+(.+?)\s*$/).flatten
  end

  def extract_campaigns(actor, page, body)
    section = extract_section(body, 'Notable Campaigns')
    return [] if section.empty?

    campaigns = []

    section.each_line do |line|
      stripped = line.strip
      next unless stripped.match?(/^\d+\.\s+/)

      ordinal = stripped[/^\d+/].to_i

      if (match = stripped.match(/^\d+\.\s+\*\*(.+?)\*\*:\s*(.+)$/))
        name = match[1].strip
        summary = match[2].strip
      else
        name = stripped.sub(/^\d+\.\s+/, '').strip
        summary = nil
      end

      campaigns << actor_context(actor, page).merge(
        ordinal: ordinal,
        name: name,
        summary: summary,
        source_section: 'Notable Campaigns',
        source_file: page[:path]
      )
    end

    campaigns
  end

  def extract_malware_and_tools(actor, page, body)
    section = extract_section(body, 'Malware and Tools')
    return [] if section.empty?

    entries = []
    category = 'General'

    section.each_line do |line|
      stripped = line.strip
      next if stripped.empty?

      if stripped.start_with?('### ')
        category = stripped.sub(/^###\s+/, '').strip
        next
      end

      next if category == 'Ransomware Tool Matrix observations'
      next unless stripped.match?(/^[-*]\s+/)

      content = stripped.sub(/^[-*]\s+/, '').strip
      if (match = content.match(/^\*\*(.+?)\*\*:\s*(.+)$/))
        name = match[1].strip
        summary = match[2].strip
      else
        name = strip_markdown(content)
        summary = nil
      end

      entries << actor_context(actor, page).merge(
        category: category,
        name: name,
        summary: summary,
        is_software: infer_software_flag(name, summary),
        source_section: 'Malware and Tools',
        source_file: page[:path]
      )
    end

    entries
  end

  def extract_attack_mappings(actor, page, body)
    {
      group_ids: extract_attack_group_ids(actor, page, body),
      techniques: extract_attack_techniques(actor, page, body)
    }
  end

  def extract_attack_group_ids(actor, page, body)
    section = extract_section(body, 'External Links')
    return [] if section.empty?

    extract_markdown_links(section).filter_map do |link|
      next unless link[:url].include?('attack.mitre.org/groups/')

      group_id = link[:url][/(G\d{4})/i, 1]
      next unless group_id

      actor_context(actor, page).merge(
        id: group_id.upcase,
        name: link[:title],
        url: link[:url],
        source_section: 'External Links',
        mapping_origin: 'external_link'
      )
    end
  end

  def extract_attack_techniques(actor, page, body)
    records = []
    records.concat(extract_attack_techniques_from_section(actor, page, extract_section(body, 'Emulating TTPs with Atomic Red Team'), 'Emulating TTPs with Atomic Red Team', 'atomic_red_team_emulation'))
    records.concat(extract_attack_techniques_from_section(actor, page, extract_section(body, 'Tactics, Techniques, and Procedures (TTPs)'), 'Tactics, Techniques, and Procedures (TTPs)', 'ttp_section'))
    dedupe_attack_mappings(records)
  end

  def extract_attack_techniques_from_section(actor, page, section, source_section, mapping_origin)
    return [] if section.empty?

    extract_markdown_links(section).filter_map do |link|
      technique_id = [link[:title], link[:url]].join(' ')[ATTACK_TECHNIQUE_PATTERN]
      next unless technique_id

      cleaned_title = link[:title].sub(/^#{Regexp.escape(technique_id)}\s*-\s*/i, '').strip
      actor_context(actor, page).merge(
        id: technique_id.upcase,
        label: extract_bold_label_for_link(section, link[:url]),
        name: cleaned_title.empty? ? nil : cleaned_title,
        url: link[:url],
        source_section: source_section,
        mapping_origin: mapping_origin
      )
    end
  end

  def extract_references(actor, page, body, ioc_section)
    references = []

    reference_section = extract_section(body, 'References')
    reference_section.each_line do |line|
      stripped = line.strip
      next unless stripped.match?(/^\d+\.\s+/)

      link = extract_first_markdown_link(stripped)
      title = stripped[/\*\*(.+?)\*\*/, 1] || link&.dig(:title) || stripped.sub(/^\d+\.\s+/, '')
      references << actor_context(actor, page).merge(
        title: strip_markdown(title),
        url: link&.dig(:url),
        kind: infer_reference_kind(strip_markdown(title), link&.dig(:url)),
        source_section: 'References',
        source_subheading: nil,
        source_file: page[:path]
      )
    end

    references.concat(extract_ioc_source_references(actor, page, ioc_section))
    dedupe_references(references)
  end

  def extract_ioc_source_references(actor, page, ioc_section)
    return [] if ioc_section.empty?

    source_block = ioc_section[/^###\s+Sources\s*$\n?(.*?)(?=^###\s+|\z)/m, 1]
    return [] unless source_block

    source_block.each_line.filter_map do |line|
      stripped = line.strip
      next unless stripped.match?(/^[-*]\s+/)

      link = extract_first_markdown_link(stripped)
      next unless link

      {
        title: link[:title],
        url: link[:url],
        kind: infer_reference_kind(link[:title], link[:url]),
        source_section: 'Notable Indicators of Compromise (IOCs)',
        source_subheading: 'Sources'
      }
    end.map do |reference|
      actor_context(actor, page).merge(reference).merge(source_file: page[:path])
    end
  end

  def actor_context(actor, page)
    {
      actor_name: actor['name'],
      actor_slug: actor['url'].sub(%r{^/}, ''),
      actor_url: actor['url'],
      actor_permalink: page[:front_matter]['permalink'] || "#{actor['url']}/"
    }
  end

  def flatten_attack_mappings(_actor, _page, attack_mappings)
    attack_mappings.fetch(:group_ids, []).map { |entry| entry.merge(mapping_type: 'group') } +
      attack_mappings.fetch(:techniques, []).map { |entry| entry.merge(mapping_type: 'technique') }
  end

  def extract_markdown_links(text)
    text.to_s.scan(/\[([^\]]+)\]\(([^\)]+)\)/).map do |title, url|
      { title: title.strip, url: url.strip }
    end
  end

  def extract_first_markdown_link(text)
    extract_markdown_links(text).first
  end

  def extract_bold_label_for_link(section, url)
    section.each_line do |line|
      next unless line.include?(url)

      label = line[/\*\*(.+?)\*\*/, 1]
      return label&.strip
    end

    nil
  end

  def infer_reference_kind(title, url)
    haystack = [title, url].compact.join(' ').downcase
    return 'advisory' if haystack.include?('advisory')
    return 'alert' if haystack.include?('alert')
    return 'report' if haystack.include?('report')
    return 'analysis' if haystack.include?('analysis')
    return 'blog' if haystack.include?('blog')

    'reference'
  end

  def infer_software_flag(name, summary)
    text = [name, summary].compact.join(' ').downcase
    return false if text.include?('affiliate program') || text.include?('living off the land') || text.include?('initial access brokers')
    return false if text.include?('social engineering') || text.include?('fast encryption') || text.include?('cryptocurrency theft')

    true
  end

  def dedupe_references(references)
    seen = {}
    references.each_with_object([]) do |reference, records|
      key = [reference[:actor_slug], reference[:title], reference[:url], reference[:source_section], reference[:source_subheading]].join('|')
      next if seen[key]

      seen[key] = true
      records << reference
    end
  end

  def dedupe_attack_mappings(records)
    seen = {}
    records.each_with_object([]) do |record, items|
      key = [record[:actor_slug], record[:id], record[:mapping_origin], record[:source_section]].join('|')
      next if seen[key]

      seen[key] = true
      items << record
    end
  end

  def unique_sorted(values)
    values.compact.reject(&:empty?).uniq.sort
  end

  def risk_levels_in_order(levels)
    order = %w[Critical High Medium Low]
    order.select { |level| levels.include?(level) }
  end

  def ioc_type_for(heading)
    normalized = heading.downcase

    return 'ip_address' if normalized.include?('ip address')
    return 'domain' if normalized.include?('domain')
    return 'md5' if normalized.include?('md5')
    return 'sha1' if normalized.include?('sha-1') || normalized.include?('sha1')
    return 'sha256' if normalized.include?('sha-256') || normalized.include?('sha256')
    return 'file_extension' if normalized.include?('file extension')
    return 'email' if normalized.include?('email')
    return 'url' if normalized == 'urls' || normalized == 'url' || normalized.include?('url ')

    normalized.gsub(/[^a-z0-9]+/, '_').gsub(/\A_|_\z/, '')
  end

  def extract_indicator_candidates(content, heading)
    candidates = []
    label = extract_label(content)
    normalized_heading = heading.to_s.downcase

    content.scan(/`([^`]+)`/).flatten.each do |value|
      inferred_type = infer_indicator_type(value, normalized_heading)
      next unless inferred_type

      candidates << { value: value, label: label, inferred_type: inferred_type }
    end

    plain_text = normalize_text_for_extraction(content)
    candidates.concat(scan_pattern_candidates(plain_text, normalized_heading, label))

    dedupe_candidates(candidates)
  end

  def scan_pattern_candidates(content, normalized_heading, label)
    candidates = []

    candidates.concat(build_candidates(content.scan(URL_PATTERN), label, 'url'))
    candidates.concat(build_candidates(content.scan(EMAIL_PATTERN), label, 'email'))
    candidates.concat(build_candidates(content.scan(CVE_PATTERN), label, 'cve'))
    candidates.concat(build_candidates(content.scan(ATTACK_TECHNIQUE_PATTERN), label, 'attack_technique'))
    candidates.concat(build_candidates(content.scan(IPV4_PATTERN).select { |value| valid_ipv4?(value) }, label, 'ip_address'))
    candidates.concat(build_candidates(content.scan(DOMAIN_PATTERN), label, 'domain'))

    if normalized_heading.include?('file extension')
      candidates.concat(build_candidates(content.scan(FILE_EXTENSION_PATTERN), label, 'file_extension'))
    end

    if normalized_heading.include?('ransom') || normalized_heading.include?('note') || normalized_heading.include?('filename')
      candidates.concat(build_candidates(content.scan(FILENAME_PATTERN), label, 'filename'))
    end

    candidates
  end

  def build_candidates(values, label, inferred_type)
    Array(values).flatten.map do |value|
      { value: value, label: label, inferred_type: inferred_type }
    end
  end

  def dedupe_candidates(candidates)
    seen = {}

    candidates.each_with_object([]) do |candidate, records|
      normalized = normalize_indicator(candidate[:value], candidate[:inferred_type])[:canonical_value]
      next if normalized.empty?

      key = [candidate[:inferred_type], normalized].join('|')
      next if seen[key]

      seen[key] = true
      records << candidate
    end
  end

  def infer_indicator_type(value, normalized_heading = nil)
    normalized_value = normalize_text_for_extraction(value)

    return 'sha256' if normalized_value.match?(/\A[a-f0-9]{64}\z/i)
    return 'sha1' if normalized_value.match?(/\A[a-f0-9]{40}\z/i)
    return 'md5' if normalized_value.match?(/\A[a-f0-9]{32}\z/i)
    return 'cve' if normalized_value.match?(CVE_PATTERN)
    return 'attack_technique' if normalized_value.match?(ATTACK_TECHNIQUE_PATTERN)
    return 'url' if normalized_value.match?(URL_PATTERN)
    return 'email' if normalized_value.match?(EMAIL_PATTERN)
    return 'ip_address' if normalized_value.match?(IPV4_PATTERN) && valid_ipv4?(normalized_value)
    return 'file_extension' if normalized_value.match?(/\A\.[a-z0-9]{2,12}\z/i)
    return 'filename' if filename_candidate?(normalized_value, normalized_heading)
    return 'domain' if normalized_value.match?(/\A#{DOMAIN_PATTERN.source}\z/i)

    nil
  end

  def filename_candidate?(value, normalized_heading)
    return false unless value.match?(/\A[\w.-]+\.[A-Za-z0-9]{2,12}\z/)
    return false if value.include?('..')
    return false if value.match?(/\A#{DOMAIN_PATTERN.source}\z/i)

    normalized_heading.to_s.include?('ransom') || normalized_heading.to_s.include?('note') || normalized_heading.to_s.include?('filename')
  end

  def normalize_indicator(value, inferred_type = nil)
    legacy_value = legacy_normalize_indicator(value)
    canonical_value = normalize_text_for_extraction(value)
    canonical_value = canonical_value.gsub(/[\]\)>.,;:]+\z/, '')
    canonical_value = canonical_value.gsub(/\A[\[(<"']+/, '')
    canonical_value = canonical_value.gsub(/["']+\z/, '')

    if %w[domain url email file_extension cve attack_technique md5 sha1 sha256].include?(inferred_type)
      canonical_value = canonical_value.downcase
    end

    lookup_keys = [canonical_value]
    lookup_keys << legacy_value if !legacy_value.empty? && legacy_value != canonical_value

    {
      canonical_value: canonical_value,
      legacy_normalized_value: legacy_value == canonical_value ? nil : legacy_value,
      lookup_keys: lookup_keys.uniq
    }
  end

  def legacy_normalize_indicator(value)
    cleaned = strip_markdown(value)
    cleaned = cleaned.gsub('[.]', '.')
    cleaned = cleaned.gsub(/^hxxps:/i, 'https:')
    cleaned = cleaned.gsub(/^hxxp:/i, 'http:')
    cleaned.strip
  end

  def normalize_text_for_extraction(text)
    strip_markdown(text)
      .gsub('[.]', '.')
      .gsub('(.)', '.')
      .gsub('[:]', ':')
      .gsub('[://]', '://')
      .gsub('[@]', '@')
      .gsub(/^hxxps:/i, 'https:')
      .gsub(/^hxxp:/i, 'http:')
      .gsub(/\s+/, ' ')
      .strip
  end

  def valid_ipv4?(value)
    value.split('.').length == 4 && value.split('.').all? { |part| part.to_i.to_s == part && part.to_i.between?(0, 255) }
  end

  def strip_markdown(text)
    text.to_s
      .gsub(/`([^`]+)`/, '\1')
      .gsub(/\*\*([^*]+)\*\*/, '\1')
      .gsub(/\[([^\]]+)\]\([^\)]+\)/, '\1')
      .gsub(/\s+/, ' ')
      .strip
  end

  def extract_label(content)
    match = content.match(/^\*\*(.+?)\*\*:/)
    match ? match[1].strip : nil
  end

  def build_mitre_collection_index(collection_dir)
    docs = []
    pattern = File.join(collection_dir, '*.md')
    Dir.glob(pattern).sort.each do |path|
      next unless File.file?(path)

      begin
        page = parse_page(path)
      rescue StandardError
        next
      end
      fm = page[:front_matter]
      mid = fm['mitre_id']
      next if mid.to_s.strip.empty?

      docs << {
        title: fm['title'],
        mitre_id: mid,
        permalink: fm['permalink'],
        mitre_url: fm['mitre_url'],
        domains: fm['domains'] || [],
        layout: fm['layout']
      }
    end
    docs
  end

  def build_actors_by_technique(actor_documents)
    out = Hash.new { |h, k| h[k] = [] }
    actor_documents.each do |ad|
      actor_technique_ids_for_index(ad).each do |tid|
        out[tid] << {
          name: ad[:name],
          permalink: ad[:permalink],
          url: ad[:url]
        }
      end
    end

    out.each_value { |list| list.uniq! { |x| [x[:name], x[:permalink]] } }
    out
  end

  def build_actors_by_tactic(actor_documents, technique_to_tactics)
    technique_to_tactics ||= {}
    out = Hash.new { |h, k| h[k] = [] }

    actor_documents.each do |ad|
      actor_technique_ids_for_index(ad).each do |tid|
        (technique_to_tactics[tid] || []).each do |ta|
          taup = ta.to_s.upcase
          next if taup.empty?

          out[taup] << {
            name: ad[:name],
            permalink: ad[:permalink],
            url: ad[:url]
          }
        end
      end
    end

    out.each_value { |list| list.uniq! { |x| [x[:name], x[:permalink]] } }
    out.sort.to_h
  end

  def actor_technique_ids_for_index(ad)
    ids = []

    Array(ad[:mitre_ttps]).each do |ttp|
      if ttp.is_a?(Hash)
        tid = (ttp['technique_id'] || ttp[:technique_id]).to_s.upcase
        ids << tid if tid =~ /\AT\d/
      elsif ttp.is_a?(String)
        match = ttp.match(/\b(T\d{4}(?:\.\d{3})?)\b/i)
        ids << match[1].upcase if match
      end
    end

    am = ad[:attack_mappings]
    if am.is_a?(Hash)
      Array(am[:techniques]).each do |rec|
        next unless rec.is_a?(Hash)

        tid = (rec[:id] || rec['id']).to_s.upcase
        ids << tid if tid =~ /\AT\d/
      end
    end

    ids.uniq
  end

  def load_newest_mitre_resolver
    manifest = newest_mitre_manifest_path
    return nil unless manifest

    yml = YAML.safe_load(File.read(manifest), permitted_classes: [Time, Date], aliases: true) || {}
    root = File.dirname(manifest)
    bundle_paths = {}
    (yml['bundles'] || {}).each do |domain, info|
      fn = info['filename']
      p = File.join(root, fn)
      bundle_paths[domain] = p if File.exist?(p)
    end
    return nil if bundle_paths.empty?

    data = MitreStixLoader.load_and_merge(bundle_paths)
    MitreRelationshipResolver.new(data[:objects], data[:relationships], data[:domains_by_id])
  rescue StandardError => e
    warn "MITRE snapshot unavailable for indexes (#{e.message})"
    nil
  end

  def newest_mitre_manifest_path
    Dir.glob('data/imports/mitre-attack/*/manifest.yml').max_by { |p| File.mtime(p) }
  end

  def resolve_mitre_resolver_for_indexes
    r = load_newest_mitre_resolver
    return r if r

    load_mitre_resolver_from_enterprise_bundle_cache
  end

  def load_mitre_resolver_from_enterprise_bundle_cache
    path = ENTERPRISE_BUNDLE_CACHE
    fetch_enterprise_attack_bundle!(path) unless File.exist?(path) && File.size(path) > 100_000
    return nil unless File.exist?(path)

    bundle_paths = { 'enterprise' => path }
    data = MitreStixLoader.load_and_merge(bundle_paths)
    MitreRelationshipResolver.new(data[:objects], data[:relationships], data[:domains_by_id])
  rescue StandardError => e
    warn "Enterprise ATT&CK bundle resolver unavailable (#{e.message})"
    nil
  end

  def fetch_enterprise_attack_bundle!(path)
    FileUtils.mkdir_p(File.dirname(path))
    uri = URI.parse(MitreCommon.bundle_url('enterprise'))
    Net::HTTP.start(uri.host, uri.port, use_ssl: uri.scheme == 'https', read_timeout: 180, open_timeout: 30) do |http|
      req = Net::HTTP::Get.new(uri)
      res = http.request(req)
      raise "HTTP #{res.code}" unless res.is_a?(Net::HTTPSuccess)

      File.binwrite(path, res.body)
    end
  end

  def build_fallback_enterprise_tactics_documents
    ENTERPRISE_TACTICS_FALLBACK.map do |tid, title, slug|
      id = tid.upcase
      {
        title: title.split('-').join(' '),
        mitre_id: id,
        permalink: "/tactics/#{id}/",
        mitre_url: "https://attack.mitre.org/tactics/#{slug}/",
        domains: ['enterprise-attack'],
        layout: 'tactic',
        shortname: slug.tr('-', '_')
      }
    end
  end

  def build_technique_tactics_map(resolver)
    h = {}
    resolver.technique_objects.each do |obj|
      next if obj['revoked'] == true || obj['x_mitre_deprecated'] == true

      eid = MitreCommon.mitre_external_id(obj)
      next unless eid&.match?(/\AT\d/i)

      tid = eid.upcase
      stix_id = obj['id']
      tas = resolver.tactics_for_technique(stix_id).map(&:upcase).uniq
      h[tid] = tas unless tas.empty?
    end
    h.sort.to_h
  end

  def build_techniques_from_resolver(resolver)
    resolver.technique_objects.filter_map do |obj|
      next if obj['revoked'] == true || obj['x_mitre_deprecated'] == true

      eid = MitreCommon.mitre_external_id(obj)
      next unless eid&.match?(/\AT\d/i)

      eidu = eid.upcase
      sid = obj['id']
      url = MitreCommon.mitre_external_url(obj) || MitreCommon.technique_url(eidu)
      {
        title: obj['name'],
        mitre_id: eidu,
        permalink: url,
        mitre_url: url,
        domains: (resolver.domains_by_id[sid] || []).uniq,
        layout: 'technique'
      }
    end.sort_by { |t| t[:mitre_id] }
  end

  def build_tactics_documents_from_resolver(resolver)
    resolver.tactic_objects.filter_map do |obj|
      next if obj['revoked'] == true || obj['x_mitre_deprecated'] == true

      eid = MitreCommon.mitre_external_id(obj)
      next unless eid&.match?(/\ATA\d/i)

      eidu = eid.upcase
      sid = obj['id']
      {
        title: obj['name'],
        mitre_id: eidu,
        permalink: "/tactics/#{eidu}/",
        mitre_url: MitreCommon.mitre_external_url(obj) || "https://attack.mitre.org/tactics/#{eidu}/",
        domains: (resolver.domains_by_id[sid] || []).uniq,
        layout: 'tactic',
        shortname: obj['x_mitre_shortname']
      }
    end.uniq { |t| t[:mitre_id] }.sort_by { |t| t[:mitre_id] }
  end

  def ensure_tactic_collection_pages(tactic_documents)
    return if tactic_documents.empty?

    FileUtils.mkdir_p(TACTICS_DIR)

    tactic_documents.each do |t|
      mid = t[:mitre_id].to_s.upcase
      path = File.join(TACTICS_DIR, "#{mid.downcase}.md")
      next if File.exist?(path)

      fm = {
        'layout' => 'tactic',
        'title' => t[:title],
        'mitre_id' => mid,
        'permalink' => "/tactics/#{mid}/",
        'mitre_url' => t[:mitre_url],
        'domains' => t[:domains] || [],
        'shortname' => t[:shortname],
        'source_attribution' => MitreCommon::SOURCE_ATTRIBUTION
      }

      body = +<<"BODY"
## Description

*Stub page generated from MITRE ATT&CK bundle metadata.* Import via `scripts/import-mitre.rb` to enrich descriptions.

## Threat actors

Threat actors in this project are listed below when their ATT&CK technique references map to this tactic.

BODY
      body << "\n---\n\n*#{MitreCommon::SOURCE_ATTRIBUTION}*\n"

      write_jekyll_markdown(path, fm, body)
    end
  end

  def write_jekyll_markdown(path, front_matter, body)
    dump = front_matter.transform_keys(&:to_s).compact
    yaml = YAML.dump(dump).sub(/\A---\n/, '')
    File.write(path, "---\n#{yaml}---\n\n#{body}")
  end

  def build_software_by_actor(actor_documents)
    actor_documents.each_with_object({}) do |ad, h|
      sw = Array(ad[:mitre_software])
      next if sw.empty?

      h[ad[:name]] = sw
    end
  end

  def build_technique_index_from_actor_yaml(actors)
    by_id = {}

    actors.each do |actor|
      Array(actor['ttps']).each do |entry|
        text = entry.to_s
        match = text.match(/\b(T\d{4}(?:\.\d{3})?)\b/i)
        next unless match

        id = match[1].upcase
        title = text.sub(match[0], '').sub(/\A\s*-\s*/, '').strip
        title = id if title.empty?

        by_id[id] ||= {
          title: title,
          mitre_id: id,
          permalink: technique_permalink_or_url(id),
          mitre_url: technique_permalink_or_url(id),
          domains: [],
          layout: 'technique'
        }
      end
    end

    by_id.values.sort_by { |entry| entry[:mitre_id].to_s }
  end

  def technique_permalink_or_url(technique_id)
    tid = technique_id.to_s.upcase
    if tid.include?('.')
      base, sub = tid.split('.', 2)
      "https://attack.mitre.org/techniques/#{base}/#{sub}/"
    else
      "https://attack.mitre.org/techniques/#{tid}/"
    end
  end

  def build_search_index(actor_documents, technique_documents, campaign_mitre_documents)
    {
      generated_at: Time.now.utc.iso8601,
      actors: actor_documents.map do |a|
        {
          kind: 'actor',
          name: a[:name],
          permalink: a[:permalink],
          description: a[:description].to_s[0..280],
          country: a[:country]
        }
      end,
      techniques: technique_documents.map do |t|
        {
          kind: 'technique',
          title: t[:title],
          mitre_id: t[:mitre_id],
          permalink: t[:permalink]
        }
      end,
      campaigns: campaign_mitre_documents.map do |c|
        {
          kind: 'campaign',
          title: c[:title],
          mitre_id: c[:mitre_id],
          permalink: c[:permalink]
        }
      end
    }
  end

  def write_json(filename, payload)
    path = File.join(OUTPUT_DIR, filename)
    FileUtils.mkdir_p(File.dirname(path))
    File.write(path, JSON.pretty_generate(payload) + "\n")
  end

  def write_api_json(filename, payload)
    path = File.join(API_DIR, filename)
    FileUtils.mkdir_p(File.dirname(path))
    File.write(path, JSON.pretty_generate(payload) + "\n")
  end

  def safe_load_yaml_file(path)
    safe_load_yaml(File.read(path))
  end

  def safe_load_yaml(content)
    YAML.safe_load(content, permitted_classes: [], aliases: false)
  end
end

ThreatActorIndexGenerator.new.run if __FILE__ == $PROGRAM_NAME
