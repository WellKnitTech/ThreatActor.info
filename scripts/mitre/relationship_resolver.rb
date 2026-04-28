# frozen_string_literal: true

require_relative 'mitre_common'

# Indexes STIX relationships and resolves MITRE external IDs via object map.
class MitreRelationshipResolver
  attr_reader :objects, :relationships, :domains_by_id

  def initialize(objects, relationships, domains_by_id)
    @objects = objects
    @relationships = relationships
    @domains_by_id = domains_by_id
    @by_source = Hash.new { |h, k| h[k] = [] }
    @by_target = Hash.new { |h, k| h[k] = [] }
    @shortname_to_tactic_id = build_shortname_to_tactic_id
    index_relationships
  end

  def object_for_stix_id(stix_id)
    @objects[stix_id]
  end

  def external_id_for(stix_id)
    obj = @objects[stix_id]
    return nil unless obj

    MitreCommon.mitre_external_id(obj)
  end

  def name_for(stix_id)
    obj = @objects[stix_id]
    obj&.fetch('name', nil)
  end

  # intrusion-set -> attack-pattern (uses)
  def group_uses_techniques(group_stix_id)
    outgoing(group_stix_id, 'uses').filter_map do |tid|
      o = @objects[tid]
      next unless o && o['type'] == 'attack-pattern'

      eid = MitreCommon.mitre_external_id(o)
      next unless eid && eid =~ /\AT\d/

      {
        'technique_id' => eid,
        'technique_name' => o['name'],
        'url' => MitreCommon.mitre_external_url(o) || MitreCommon.technique_url(eid),
        'stix_id' => tid
      }
    end.uniq { |r| r['technique_id'] }
  end

  # intrusion-set -> malware|tool
  def group_uses_software(group_stix_id)
    outgoing(group_stix_id, 'uses').filter_map do |sid|
      o = @objects[sid]
      next unless o && %w[malware tool].include?(o['type'])

      eid = MitreCommon.mitre_external_id(o)
      next unless eid && eid =~ /\AS\d/

      {
        'name' => o['name'],
        'mitre_id' => eid,
        'url' => MitreCommon.mitre_external_url(o) || "https://attack.mitre.org/software/#{eid}/",
        'type' => MitreCommon.software_type_label(o),
        'stix_id' => sid,
        'description' => MitreCommon.clean_description(o['description']).to_s[0..500]
      }
    end.uniq { |r| r['mitre_id'] }
  end

  # campaigns attributed to group: campaign -attributed-to-> intrusion-set
  def campaigns_for_group(group_stix_id)
    incoming(group_stix_id, 'attributed-to').filter_map do |cid|
      o = @objects[cid]
      next unless o && o['type'] == 'campaign'

      eid = MitreCommon.mitre_external_id(o)
      next unless eid && eid =~ /\AC\d/

      {
        'name' => o['name'],
        'campaign_id' => eid,
        'url' => MitreCommon.mitre_external_url(o) || "https://attack.mitre.org/campaigns/#{eid}/",
        'stix_id' => cid,
        'description' => MitreCommon.clean_description(o['description']).to_s[0..500]
      }
    end.uniq { |r| r['campaign_id'] }
  end

  # technique -> mitigations (course-of-action mitigates attack-pattern): incoming to technique
  def mitigations_for_technique(technique_stix_id)
    incoming(technique_stix_id, 'mitigates').filter_map do |mid|
      o = @objects[mid]
      next unless o && o['type'] == 'course-of-action'

      eid = MitreCommon.mitre_external_id(o)
      next unless eid && eid =~ /\AM\d/

      {
        'name' => o['name'],
        'mitre_id' => eid,
        'url' => MitreCommon.mitre_external_url(o) || "https://attack.mitre.org/mitigations/#{eid}/",
        'stix_id' => mid
      }
    end.uniq { |r| r['mitre_id'] }
  end

  # subtechnique (source) -subtechnique-of-> parent (target)
  def parent_technique_stix_id(subtechnique_stix_id)
    outgoing(subtechnique_stix_id, 'subtechnique-of').each do |pid|
      o = @objects[pid]
      return pid if o && o['type'] == 'attack-pattern'
    end
    nil
  end

  # attack-pattern -> subtechniques
  def subtechnique_stix_ids(parent_stix_id)
    incoming(parent_stix_id, 'subtechnique-of')
  end

  # Groups that use this technique (attack-pattern)
  def groups_using_technique(technique_stix_id)
    incoming(technique_stix_id, 'uses').select do |gid|
      o = @objects[gid]
      o && o['type'] == 'intrusion-set'
    end
  end

  # Groups / campaigns using software
  def groups_using_software(software_stix_id)
    incoming(software_stix_id, 'uses').select do |gid|
      o = @objects[gid]
      o && o['type'] == 'intrusion-set'
    end
  end

  def tactics_for_technique(technique_stix_id)
    obj = @objects[technique_stix_id]
    return [] unless obj

    phases = obj['kill_chain_phases'] || []
    tactics = []
    phases.each do |ph|
      next unless ph.is_a?(Hash)

      name = ph['phase_name']
      tid = @shortname_to_tactic_id[name]
      tactics << tid if tid
    end
    tactics.compact.uniq
  end

  def tactic_objects
    @objects.values.select { |o| o['type'] == 'x-mitre-tactic' }
  end

  def technique_objects
    @objects.values.select { |o| o['type'] == 'attack-pattern' && MitreCommon.mitre_external_id(o).to_s =~ /\AT\d/ }
  end

  def campaign_objects
    @objects.values.select { |o| o['type'] == 'campaign' }
  end

  def mitigation_objects
    @objects.values.select { |o| o['type'] == 'course-of-action' }
  end

  def software_objects
    @objects.values.select { |o| %w[malware tool].include?(o['type']) }
  end

  def intrusion_sets
    @objects.values.select { |o| o['type'] == 'intrusion-set' }
  end

  private

  def build_shortname_to_tactic_id
    h = {}
    @objects.each do |_id, obj|
      next unless obj['type'] == 'x-mitre-tactic'

      eid = MitreCommon.mitre_external_id(obj)
      short = obj['x_mitre_shortname']
      h[short] = eid if short && eid && eid =~ /\ATA\d/i
    end
    h
  end

  def index_relationships
    @relationships.each do |rel|
      next unless rel.is_a?(Hash)
      next if rel['revoked'] == true

      stype = rel['relationship_type'].to_s
      src = rel['source_ref']
      tgt = rel['target_ref']
      next if src.nil? || tgt.nil?

      @by_source[src] << [stype, tgt]
      @by_target[tgt] << [stype, src]
    end
  end

  def outgoing(stix_id, rel_type)
    @by_source[stix_id].select { |t, _| t == rel_type }.map(&:last)
  end

  def incoming(stix_id, rel_type)
    @by_target[stix_id].select { |t, _| t == rel_type }.map(&:last)
  end
end
