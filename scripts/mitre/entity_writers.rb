# frozen_string_literal: true

require 'fileutils'
require 'json'
require 'yaml'
require_relative 'mitre_common'

# Writes Jekyll collection markdown for MITRE ATT&CK objects.
class MitreEntityWriters
  DIRS = {
    techniques: '_techniques',
    tactics: '_tactics',
    campaigns: '_campaigns',
    mitigations: '_mitigations',
    malware: '_malware'
  }.freeze

  attr_reader :resolver, :domains_by_id, :group_slug_map, :skip_revoked

  # group_slug_map: intrusion-set-stix-id => { 'name' =>, 'url' => '/apt0001/' }
  def initialize(resolver, domains_by_id, group_slug_map:, skip_revoked: true)
    @resolver = resolver
    @domains_by_id = domains_by_id
    @group_slug_map = group_slug_map || {}
    @skip_revoked = skip_revoked
  end

  def write_techniques!
    count = 0
    resolver.technique_objects.each do |obj|
      next if skip_obj?(obj)

      eid = MitreCommon.mitre_external_id(obj)
      next unless eid =~ /\AT\d/i

      write_technique_file(obj, eid)
      count += 1
    end
    count
  end

  def write_tactics!
    count = 0
    resolver.tactic_objects.each do |obj|
      next if skip_obj?(obj)

      eid = MitreCommon.mitre_external_id(obj)
      next unless eid =~ /\ATA\d/i

      write_tactic_file(obj, eid)
      count += 1
    end
    count
  end

  def write_campaigns!
    count = 0
    resolver.campaign_objects.each do |obj|
      next if skip_obj?(obj)

      eid = MitreCommon.mitre_external_id(obj)
      next unless eid =~ /\AC\d/i

      write_campaign_file(obj, eid)
      count += 1
    end
    count
  end

  def write_mitigations!
    count = 0
    resolver.mitigation_objects.each do |obj|
      next if skip_obj?(obj)

      eid = MitreCommon.mitre_external_id(obj)
      next unless eid =~ /\AM\d/i

      write_mitigation_file(obj, eid)
      count += 1
    end
    count
  end

  # Writes MITRE software to _malware; merges attribution into existing pages when possible.
  def write_software!(force_description: false)
    count = 0
    resolver.software_objects.each do |obj|
      next if skip_obj?(obj)

      eid = MitreCommon.mitre_external_id(obj)
      next unless eid =~ /\AS\d/i

      write_software_file(obj, eid, force_description: force_description)
      count += 1
    end
    count
  end

  private

  def skip_obj?(obj)
    return true if skip_revoked && (obj['revoked'] == true || obj['x_mitre_deprecated'] == true)

    false
  end

  def domains_for(stix_id)
    list = domains_by_id[stix_id] || []
    inferred = MitreCommon.infer_domain_key_from_object(resolver.object_for_stix_id(stix_id) || {})
    (list + inferred).uniq
  end

  def technique_filename(eid)
    eid.gsub('.', '-').downcase
  end

  def permalink_technique(eid)
    "/techniques/#{eid}/"
  end

  def write_technique_file(obj, eid)
    stix_id = obj['id']
    domains = domains_for(stix_id)
    desc = MitreCommon.clean_description(obj['description'])
    url = MitreCommon.mitre_external_url(obj) || MitreCommon.technique_url(eid)
    parent_sid = resolver.parent_technique_stix_id(stix_id)
    parent_eid = parent_sid ? MitreCommon.mitre_external_id(resolver.object_for_stix_id(parent_sid)) : nil
    is_sub = obj['x_mitre_is_subtechnique'] == true || eid.include?('.')
    tactic_ids = resolver.tactics_for_technique(stix_id)
    mits = resolver.mitigations_for_technique(stix_id)
    subs = resolver.subtechnique_stix_ids(stix_id).filter_map do |sid|
      o = resolver.object_for_stix_id(sid)
      next unless o

      xeid = MitreCommon.mitre_external_id(o)
      next unless xeid

      { 'id' => xeid, 'name' => o['name'], 'permalink' => permalink_technique(xeid) }
    end

    groups = resolver.groups_using_technique(stix_id).filter_map do |gid|
      meta = group_slug_map[gid]
      next unless meta

      { 'name' => meta['name'], 'url' => meta['url'] }
    end

    fm = {
      'layout' => 'technique',
      'title' => obj['name'].to_s.gsub('"', '\"'),
      'mitre_id' => eid.upcase,
      'permalink' => permalink_technique(eid.upcase),
      'mitre_url' => url,
      'domains' => domains,
      'tactic_ids' => tactic_ids.map(&:upcase),
      'is_subtechnique' => is_sub,
      'parent_mitre_id' => parent_eid&.upcase,
      'source_attribution' => MitreCommon::SOURCE_ATTRIBUTION,
      'description_excerpt' => desc.to_s[0..280].gsub('"', '\"')
    }

    body = +<<"BODY"
## Description

#{desc.empty? ? '*No description.*' : desc}

BODY

    unless subs.empty?
      body << "### Sub-techniques\n\n"
      subs.sort_by { |s| s['id'] }.each do |s|
        body << "- [#{s['name']}](#{s['permalink']}) (`#{s['id']}`)\n"
      end
      body << "\n"
    end

    unless mits.empty?
      body << "### Mitigations\n\n"
      mits.sort_by { |m| m['mitre_id'] }.each do |m|
        body << "- [#{m['name']}](/mitigations/#{m['mitre_id']}/) (`#{m['mitre_id']}`)\n"
      end
      body << "\n"
    end

    unless groups.empty?
      body << "### Groups\n\n"
      groups.sort_by { |g| g['name'].to_s.downcase }.each do |g|
        body << "- [#{g['name']}](#{g['url']})\n"
      end
      body << "\n"
    end

    body << "\n---\n\n"
    body << "*#{MitreCommon::SOURCE_ATTRIBUTION}*\n"

    path = File.join(DIRS[:techniques], "#{technique_filename(eid)}.md")
    write_front_matter_page(path, fm, body)

    data_path = File.join(DIRS[:techniques], "#{technique_filename(eid)}.data.json")
    File.write(data_path, JSON.pretty_generate({ mitre_id: eid.upcase, mitigations: mits, subtechniques: subs, groups: groups }))
  end

  def write_tactic_file(obj, eid)
    stix_id = obj['id']
    domains = domains_for(stix_id)
    desc = MitreCommon.clean_description(obj['description'])
    url = MitreCommon.mitre_external_url(obj) || "https://attack.mitre.org/tactics/#{eid}/"
    shortname = obj['x_mitre_shortname']

    fm = {
      'layout' => 'tactic',
      'title' => obj['name'].to_s.gsub('"', '\"'),
      'mitre_id' => eid.upcase,
      'permalink' => "/tactics/#{eid.upcase}/",
      'mitre_url' => url,
      'domains' => domains,
      'shortname' => shortname,
      'source_attribution' => MitreCommon::SOURCE_ATTRIBUTION
    }

    body = +<<"BODY"
## Description

#{desc.empty? ? '*No description.*' : desc}

---

*#{MitreCommon::SOURCE_ATTRIBUTION}*
BODY

    path = File.join(DIRS[:tactics], "#{eid.downcase}.md")
    write_front_matter_page(path, fm, body)
  end

  def write_campaign_file(obj, eid)
    stix_id = obj['id']
    domains = domains_for(stix_id)
    desc = MitreCommon.clean_description(obj['description'])
    url = MitreCommon.mitre_external_url(obj) || "https://attack.mitre.org/campaigns/#{eid}/"

    fm = {
      'layout' => 'campaign',
      'title' => obj['name'].to_s.gsub('"', '\"'),
      'mitre_id' => eid.upcase,
      'permalink' => "/campaigns/#{eid.upcase}/",
      'mitre_url' => url,
      'domains' => domains,
      'source_attribution' => MitreCommon::SOURCE_ATTRIBUTION
    }

    body = +<<"BODY"
## Description

#{desc.empty? ? '*No description.*' : desc}

---

*#{MitreCommon::SOURCE_ATTRIBUTION}*
BODY

    path = File.join(DIRS[:campaigns], "#{eid.downcase}.md")
    write_front_matter_page(path, fm, body)
  end

  def write_mitigation_file(obj, eid)
    stix_id = obj['id']
    domains = domains_for(stix_id)
    desc = MitreCommon.clean_description(obj['description'])
    url = MitreCommon.mitre_external_url(obj) || "https://attack.mitre.org/mitigations/#{eid}/"

    fm = {
      'layout' => 'mitigation',
      'title' => obj['name'].to_s.gsub('"', '\"'),
      'mitre_id' => eid.upcase,
      'permalink' => "/mitigations/#{eid.upcase}/",
      'mitre_url' => url,
      'domains' => domains,
      'source_attribution' => MitreCommon::SOURCE_ATTRIBUTION
    }

    body = +<<"BODY"
## Description

#{desc.empty? ? '*No description.*' : desc}

---

*#{MitreCommon::SOURCE_ATTRIBUTION}*
BODY

    path = File.join(DIRS[:mitigations], "#{eid.downcase}.md")
    write_front_matter_page(path, fm, body)
  end

  def write_software_file(obj, eid, force_description: false)
    stix_id = obj['id']
    name = obj['name'].to_s
    slug = slugify(name)
    return if slug.empty?

    domains = domains_for(stix_id)
    desc = MitreCommon.clean_description(obj['description'])
    url = MitreCommon.mitre_external_url(obj) || "https://attack.mitre.org/software/#{eid}/"
    path = File.join(DIRS[:malware], "#{slug}.md")

    groups = resolver.groups_using_software(stix_id).filter_map do |gid|
      m = group_slug_map[gid]
      next unless m

      { 'name' => m['name'], 'url' => m['url'], 'country' => nil, 'risk_level' => nil }
    end

    if File.exist?(path)
      merge_malware_front_matter(path, eid, url, domains, desc, force_description: force_description)
    else
      fm = {
        'layout' => 'malware',
        'title' => name.gsub('"', '\"'),
        'category' => obj['type'] == 'tool' ? 'Tool' : 'Malware',
        'mitre_id' => eid.upcase,
        'mitre_url' => url,
        'domains' => domains,
        'permalink' => "/malware/#{slug}/",
        'actor_count' => groups.size,
        'actors' => groups.map { |g| { 'name' => g['name'], 'url' => g['url'] } },
        'source_attribution' => MitreCommon::SOURCE_ATTRIBUTION,
        'summary' => desc[0..400].gsub('"', '\"')
      }

      body = +<<"BODY"
## Overview

#{desc.empty? ? '*No description.*' : desc}

## Threat Actors

#{groups.empty? ? '*No mapped threat actors.*' : groups.map { |g| "- [#{g['name']}](#{g['url']})" }.join("\n")}

---

*#{MitreCommon::SOURCE_ATTRIBUTION}*
BODY

      write_front_matter_page(path, fm, body)
    end

    data_path = File.join(DIRS[:malware], "#{slug}.data.json")
    File.write(data_path, JSON.pretty_generate({ name: name, slug: slug, mitre_id: eid.upcase, actors: groups }))
  end

  def merge_malware_front_matter(path, eid, url, domains, desc, force_description: false)
    content = File.read(path)
    parts = content.split(/^---\s*$/m, 3)
    return unless parts.size >= 3

    fm = YAML.safe_load(parts[1], permitted_classes: [Date, Time], aliases: true) || {}
    body = parts[2].to_s
    fm['mitre_id'] ||= eid.upcase
    fm['mitre_url'] ||= url
    fm['domains'] = ((fm['domains'] || []) + domains).uniq if domains.any?
    fm['source_attribution'] ||= MitreCommon::SOURCE_ATTRIBUTION
    if force_description && !desc.empty?
      fm['summary'] = desc[0..400]
    end
    write_front_matter_page(path, fm, body)
  end

  def slugify(name)
    name.to_s.downcase.gsub(/[^a-z0-9]+/, '-').gsub(/^-|-$/, '')
  end

  def write_front_matter_page(path, fm_hash, body)
    FileUtils.mkdir_p(File.dirname(path))
    yml = fm_hash.transform_keys(&:to_s).to_yaml
    yml = yml.sub(/\A---\s*\n?/, '').sub(/\.\.\.\s*\z/, '')
    File.write(path, +"---\n#{yml}---\n\n#{body}")
  end
end
