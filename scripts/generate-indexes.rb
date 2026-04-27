#!/usr/bin/env ruby

require 'json'
require 'yaml'
require 'fileutils'
require_relative 'actor_store'

class ThreatActorIndexGenerator
  PAGES_GLOB = '_threat_actors/*.md'.freeze
  OUTPUT_DIR = '_data/generated'.freeze
  API_DIR = 'api'.freeze
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

  def initialize
    @actors = load_actors
    @pages = load_pages
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

    ioc_lookup = build_ioc_lookup(ioc_documents)
    ioc_type_manifest = build_ioc_type_manifest(ioc_documents)

    write_json('threat_actors.json', actor_documents)
    write_json('iocs.json', ioc_documents)
    
    # Build facets with malware counts
    facets = build_facets(actor_documents, ioc_documents)
    facets[:malware_counts] = build_malware_counts(malware_documents)
    write_json('facets.json', facets)
    
    write_json('campaigns.json', campaign_documents)
    write_json('malware.json', malware_documents)
    write_json('attack_mappings.json', attack_mapping_documents)
    write_json('references.json', reference_documents)
    write_json('ioc_lookup.json', ioc_lookup)
    write_json('ioc_types.json', ioc_type_manifest)
    write_ioc_type_shards(ioc_documents)
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
      attack_mapping_count: attack_mappings.values.flatten.length
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
        iocs: iocs.length
      },
      # Precomputed counts for sidebar
      country_counts: country_counts,
      risk_counts: risk_counts,
      sector_counts: sector_counts
    }
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
      manifest[type] = {
        type: type,
        count: type_iocs.length,
        atomic_count: type_iocs.count { |ioc| ioc[:atomic] },
        unique_values: type_iocs.map { |ioc| ioc[:normalized_value] }.uniq.length,
        path: "/api/iocs/by-type/#{type}.json"
      }
    end
  end

  def write_ioc_type_shards(iocs)
    clear_existing_shards(TYPE_SHARDS_DIR)
    clear_existing_shards(API_TYPE_SHARDS_DIR)

    iocs.group_by { |ioc| ioc[:type] }.each do |type, type_iocs|
      payload = {
        type: type,
        count: type_iocs.length,
        atomic_count: type_iocs.count { |ioc| ioc[:atomic] },
        unique_values: type_iocs.map { |ioc| ioc[:normalized_value] }.uniq.length,
        records: type_iocs
      }

      write_json(File.join('iocs_by_type', "#{type}.json"), payload)
      write_api_json(File.join('iocs', 'by-type', "#{type}.json"), payload)
    end
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
