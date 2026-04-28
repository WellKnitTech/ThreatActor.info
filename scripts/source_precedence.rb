#!/usr/bin/env ruby
# frozen_string_literal: true

require 'time'

module SourcePrecedence
  AUTOMATED_SOURCE_NAMES = [
    'APT Groups & Operations Spreadsheet',
    'APTnotes',
    'ETDA / ThaiCERT Threat Group Cards',
    'MISP Galaxy',
    'MITRE ATT&CK',
    'Malpedia (Fraunhofer FKIE)',
    'RansomLook'
  ].freeze
  ANALYST_SOURCE_NAME = 'Analyst Notes'.freeze
  LEGACY_ANALYST_SOURCE_NAMES = ['AnalystNotes', 'Analyst Note'].freeze
  MANUAL_SOURCE_NAMES = ['Manual Entry'].freeze
  SECONDARY_SOURCE_NAMES = (MANUAL_SOURCE_NAMES + [ANALYST_SOURCE_NAME] + LEGACY_ANALYST_SOURCE_NAMES).freeze

  module_function

  def normalize_source_name(value)
    stripped = value.to_s.strip
    return ANALYST_SOURCE_NAME if LEGACY_ANALYST_SOURCE_NAMES.include?(stripped)

    stripped
  end

  def normalize_actor!(actor)
    normalized = normalize_source_name(actor['source_name'])
    actor['source_name'] = normalized unless normalized.empty?
    actor
  end

  def secondary_source?(actor)
    SECONDARY_SOURCE_NAMES.include?(normalize_source_name(actor['source_name']))
  end

  def automated_source?(actor)
    automated_source_name?(actor['source_name'])
  end

  def automated_source_name?(source_name)
    AUTOMATED_SOURCE_NAMES.include?(normalize_source_name(source_name))
  end

  def apply_takeover!(updates, existing_actor, source_name:, source_attribution:, source_record_url: nil,
                      source_license: nil, source_license_url: nil, automated_description: nil,
                      automated_label: nil)
    normalize_actor!(existing_actor)
    return updates unless secondary_source?(existing_actor)

    existing_notes = existing_actor['analyst_notes'].to_s.strip
    takeover_notes = takeover_note_parts(existing_actor, automated_label || source_name).join("\n")
    updates['analyst_notes'] = if existing_notes.empty?
                                 takeover_notes
                               else
                                 "#{existing_notes}\n\n---\n\n#{takeover_notes}"
                               end

    description = automated_description.to_s.strip
    updates['description'] = description unless description.empty?
    updates['source_name'] = source_name
    updates['source_attribution'] = source_attribution
    updates['source_record_url'] = source_record_url unless source_record_url.to_s.empty?
    updates['source_license'] = source_license unless source_license.to_s.empty?
    updates['source_license_url'] = source_license_url unless source_license_url.to_s.empty?
    provenance = existing_actor['provenance'].is_a?(Hash) ? existing_actor['provenance'].dup : {}
    provenance['manual_takeover'] = {
      'source_name' => source_name,
      'takeover_at' => Time.now.utc.strftime('%Y-%m-%dT%H:%M:%SZ')
    }
    updates['provenance'] = provenance
    updates
  end

  def build_malware_entry(name, source_name:, provenance: {}, summary: nil, category: nil, note_origin: nil,
                          source_attribution: nil, source_record_url: nil)
    entry = {
      'name' => name.to_s.strip,
      'source_name' => normalize_source_name(source_name),
      'provenance' => provenance.reject { |_key, value| blank?(value) }
    }
    entry['summary'] = summary.to_s.strip unless summary.to_s.strip.empty?
    entry['category'] = category.to_s.strip unless category.to_s.strip.empty?
    entry['note_origin'] = note_origin.to_s.strip unless note_origin.to_s.strip.empty?
    entry['source_attribution'] = source_attribution.to_s.strip unless source_attribution.to_s.strip.empty?
    entry['source_record_url'] = source_record_url.to_s.strip unless source_record_url.to_s.strip.empty?
    entry.reject { |_key, value| blank?(value) }
  end

  def merge_malware_entries(existing, incoming)
    merged = Array(existing).map { |entry| normalize_malware_entry(entry) }.reject { |entry| entry['name'].to_s.empty? }
    seen = merged.each_with_object({}) { |entry, memo| memo[entry['name'].downcase] = entry }

    Array(incoming).each do |entry|
      normalized = normalize_malware_entry(entry)
      name_key = normalized['name'].to_s.downcase
      next if name_key.empty?

      if seen[name_key]
        existing = seen[name_key]
        if automated_source_name?(normalized['source_name']) && !automated_source_name?(existing['source_name'])
          analyst_origin = existing['note_origin'] || existing['origin'] || 'analyst_note'
          preserved = existing.reject { |_key, value| blank?(value) }
          existing.replace(normalized.merge('supersedes' => analyst_origin, 'analyst_note' => preserved))
        else
          existing.merge!(normalized) { |_key, old_value, new_value| blank?(old_value) ? new_value : old_value }
        end
      else
        merged << normalized
        seen[name_key] = normalized
      end
    end

    merged
  end

  def normalize_malware_entry(entry)
    unless entry.is_a?(Hash)
      return build_malware_entry(
        entry.to_s.strip,
        source_name: ANALYST_SOURCE_NAME,
        note_origin: 'legacy_actor_malware'
      )
    end

    normalized = entry.transform_keys(&:to_s)
    normalized['name'] = normalized['name'].to_s.strip
    normalized['source_name'] = normalize_source_name(normalized['source_name'])
    normalized.reject { |_key, value| blank?(value) }
  end

  def automated_source_name?(source_name)
    AUTOMATED_SOURCE_NAMES.include?(normalize_source_name(source_name))
  end

  def blank?(value)
    value.nil? || value == '' || value == [] || value == {}
  end

  def takeover_note_parts(actor, automated_label)
    parts = []
    parts << "Previous description: #{actor['description']}" unless actor['description'].to_s.strip.empty?
    aliases = Array(actor['aliases']).reject { |entry| entry.to_s.strip.empty? }
    parts << "Previous aliases: #{aliases.join(', ')}" unless aliases.empty?
    parts << "Previous country: #{actor['country']}" unless actor['country'].to_s.strip.empty?
    sectors = Array(actor['sector_focus']).reject { |entry| entry.to_s.strip.empty? }
    parts << "Previous sectors: #{sectors.join(', ')}" unless sectors.empty?
    targets = Array(actor['targeted_victims']).reject { |entry| entry.to_s.strip.empty? }
    parts << "Previous targets: #{targets.join(', ')}" unless targets.empty?
    activity = []
    activity << "first seen: #{actor['first_seen']}" unless actor['first_seen'].to_s.strip.empty?
    activity << "last active: #{actor['last_activity']}" unless actor['last_activity'].to_s.strip.empty?
    parts << "Previous activity: #{activity.join(', ')}" unless activity.empty?
    parts << "Previous external ID: #{actor['external_id']}" unless actor['external_id'].to_s.strip.empty?
    parts << "Previous reference: #{actor['external_url']}" unless actor['external_url'].to_s.strip.empty?
    parts << ""
    parts << "=== Automated import from #{automated_label} ==="
    parts
  end
end
