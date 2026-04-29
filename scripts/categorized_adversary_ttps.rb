# frozen_string_literal: true

require 'json'
require 'set'
require 'yaml'

# Loads tropChaud/Categorized-Adversary-TTPs snapshot (MIT) and builds indexes for site/API.
module CategorizedAdversaryTtps
  ROOT = File.expand_path('..', __dir__)
  DEFAULT_SNAPSHOT = File.join(ROOT, 'data/imports/categorized-adversary-ttps/Categorized_Adversary_TTPs.json')
  MANIFEST_PATH = File.join(ROOT, 'data/imports/categorized-adversary-ttps/manifest.yml')
  MITRE_GROUP_RE = %r{/groups/(G\d{4})}i.freeze
  TECHNIQUE_RE = /\AT\d{4}(?:\.\d{3})?\z/i.freeze

  module_function

  def normalize_technique_id(str)
    u = str.to_s.strip.upcase
    return nil unless TECHNIQUE_RE.match?(u)

    u
  end

  def extract_group_id(mitre_url)
    return nil if mitre_url.nil?

    m = MITRE_GROUP_RE.match(mitre_url.to_s)
    m ? m[1].upcase : nil
  end

  def uniq_strings(arr)
    Array(arr).map(&:to_s).map(&:strip).reject(&:empty?).uniq
  end

  def merge_row(into, row)
    techs = uniq_strings(Array(row['mitre_attack_ttps']).filter_map { |t| normalize_technique_id(t) })
    into[:mitre_attack_ttps] |= techs
    into[:motivation] |= uniq_strings(row['motivation'])
    into[:victim_industries] |= uniq_strings(row['victim_industries'])
    into[:victim_countries] |= uniq_strings(row['victim_countries'])

    into[:mitre_attack_name] = row['mitre_attack_name'].to_s.strip if into[:mitre_attack_name].to_s.strip.empty? && !row['mitre_attack_name'].to_s.strip.empty?
    into[:mitre_url] ||= row['mitre_url'].to_s.strip
    into[:country] ||= row['country'].to_s.strip
    into[:etda_name] ||= row['etda_name'].to_s.strip
    into[:etda_url] ||= row['etda_url'].to_s.strip
    into[:etda_first_seen] ||= row['etda_first_seen'].to_s.strip
    into
  end

  def load_manifest
    return {} unless File.file?(MANIFEST_PATH)

    YAML.safe_load(File.read(MANIFEST_PATH), permitted_classes: [], aliases: false) || {}
  rescue StandardError => e
    warn "Categorized Adversary TTPs: manifest read failed (#{e.message})"
    {}
  end

  def load_records(path = DEFAULT_SNAPSHOT)
    return [] unless File.file?(path)

    data = JSON.parse(File.read(path))
    raise 'Expected JSON array' unless data.is_a?(Array)

    data
  rescue StandardError => e
    warn "Categorized Adversary TTPs: could not load #{path}: #{e.message}"
    []
  end

  # Returns merged rows keyed by G#### (uppercase).
  def merge_records_by_group(records)
    merged = {}
    Array(records).each do |row|
      gid = extract_group_id(row['mitre_url'])
      next unless gid

      merged[gid] ||= {
        mitre_group_id: gid,
        mitre_attack_name: '',
        mitre_url: '',
        mitre_attack_ttps: [],
        motivation: [],
        victim_industries: [],
        victim_countries: [],
        country: nil,
        etda_name: '',
        etda_url: '',
        etda_first_seen: ''
      }
      merge_row(merged[gid], row)
    end
    merged
  end

  def build_pivots(merged_by_group)
    pivot_industry = Hash.new { |h, k| h[k] = Hash.new(0) }
    pivot_motivation = Hash.new { |h, k| h[k] = Hash.new(0) }
    pivot_country = Hash.new { |h, k| h[k] = Hash.new(0) }

    merged_by_group.each_value do |g|
      techs = Array(g[:mitre_attack_ttps])
      next if techs.empty?

      industries = Array(g[:victim_industries])
      motivations = Array(g[:motivation])
      victims = Array(g[:victim_countries])

      techs.each do |tid|
        industries.each { |ind| pivot_industry[ind][tid] += 1 }
        motivations.each { |mot| pivot_motivation[mot][tid] += 1 }
        victims.each { |vc| pivot_country[vc][tid] += 1 }
      end
    end

    [pivot_industry, pivot_motivation, pivot_country].map { |p| stringify_nested_counts(p) }
  end

  def stringify_nested_counts(pivot)
    out = {}
    pivot.keys.sort.each do |label|
      inner = {}
      pivot[label].keys.sort.each { |tid| inner[tid] = pivot[label][tid] }
      out[label] = inner
    end
    out
  end

  def build_by_group_public(merged_by_group)
    merged_by_group.transform_values do |g|
      gid = g[:mitre_group_id].to_s.upcase
      ttps = Array(g[:mitre_attack_ttps]).sort
      murl = g[:mitre_url].to_s.strip
      murl = "https://attack.mitre.org/groups/#{gid}" if murl.empty? && gid.match?(/\AG\d{4}\z/)
      {
        mitre_group_id: gid,
        mitre_attack_name: g[:mitre_attack_name].to_s,
        mitre_url: murl,
        mitre_attack_ttps: ttps,
        technique_count: ttps.length,
        motivation: Array(g[:motivation]).sort,
        victim_industries: Array(g[:victim_industries]).sort,
        victim_countries: Array(g[:victim_countries]).sort,
        country: g[:country].to_s,
        etda_name: g[:etda_name].to_s,
        etda_url: g[:etda_url].to_s,
        etda_first_seen: g[:etda_first_seen].to_s
      }
    end
  end

  def compact_for_actor_api(entry)
    return nil if entry.nil?

    {
      mitre_group_id: entry[:mitre_group_id],
      mitre_attack_name: entry[:mitre_attack_name],
      mitre_url: entry[:mitre_url],
      technique_count: entry[:technique_count],
      motivation: entry[:motivation],
      victim_industries: entry[:victim_industries],
      victim_countries: entry[:victim_countries],
      country: entry[:country],
      etda_name: entry[:etda_name],
      etda_url: entry[:etda_url],
      source: 'tropChaud/Categorized-Adversary-TTPs'
    }
  end

  # Attach compact categorized_adversary_ttps to each actor document when mitre_id matches G####.
  # Distinct MITRE group IDs (G####) declared on project actor documents.
  def project_mitre_group_ids(actor_documents)
    actor_documents.each_with_object(Set.new) do |doc, acc|
      gid = doc[:mitre_id] || doc[:external_id]
      gid = gid.to_s.upcase.strip if gid
      acc << gid if gid&.match?(/\AG\d{4}\z/)
    end
  end

  def attach_to_actor_documents!(actor_documents, by_group_public)
    actor_documents.each do |doc|
      gid = doc[:mitre_id] || doc[:external_id]
      gid = gid.to_s.upcase.strip if gid
      next unless gid&.match?(/\AG\d{4}\z/)

      pub = by_group_public[gid]
      next unless pub

      summary = compact_for_actor_api(pub)
      doc[:categorized_adversary_ttps] = summary if summary
    end
    actor_documents
  end

  def integrate(actor_documents, snapshot_path = DEFAULT_SNAPSHOT)
    records = load_records(snapshot_path)
    merged = merge_records_by_group(records)
    by_group_public = build_by_group_public(merged)

    project_ids = project_mitre_group_ids(actor_documents)
    merged_for_pivots = merged.select { |gid, _| project_ids.include?(gid) }
    piv_ind, piv_mot, piv_ctry = build_pivots(merged_for_pivots)

    manifest = load_manifest

    attach_to_actor_documents!(actor_documents, by_group_public)

    meta = {
      snapshot_retrieved_at: manifest['retrieved_at'],
      source_repository: manifest['source_repository'],
      source_json_url: manifest['source_json_url'],
      license: manifest['license'],
      upstream_license_url: manifest['upstream_license_url'],
      group_count: by_group_public.length,
      pivot_eligible_group_count: merged_for_pivots.length,
      project_mitre_group_count: project_ids.length
    }

    {
      by_group: by_group_public,
      pivot_by_industry: piv_ind,
      pivot_by_motivation: piv_mot,
      pivot_by_victim_country: piv_ctry,
      meta: meta
    }
  end
end
