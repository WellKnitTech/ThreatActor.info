# frozen_string_literal: true

require_relative '../actor_store'
require_relative 'alias_resolver'

module ActorDuplicateAudit
  module_function

  def report(actors)
    index = AliasResolver.build_alias_index(actors, synonym_path: nil)
    groups = index.each_with_object([]) do |(key, positions), out|
      positions = positions.uniq.sort
      next if positions.length < 2

      out << {
        'key' => key,
        'actors' => positions.map do |position|
          actor = actors.fetch(position)
          {
            'position' => position,
            'source_file' => actor['_source_file'],
            'name' => actor['name'],
            'url' => actor['url'],
            'aliases' => Array(actor['aliases']),
            'mitre_id' => actor['mitre_id'],
            'external_id' => actor['external_id']
          }
        end
      }
    end.sort_by { |group| group['key'] }

    name_groups = duplicate_groups(actors) { |actor| AliasResolver.canonical_key(actor['name']) }
    url_groups = duplicate_groups(actors) { |actor| actor['url'].to_s.strip }

    {
      'schema_version' => 1,
      'actor_count' => actors.length,
      'normalized_key_count' => index.length,
      'collision_group_count' => groups.length,
      'collision_actor_count' => groups.flat_map { |group| group['actors'] }
                                    .map { |actor| actor['position'] }.uniq.length,
      'duplicate_name_group_count' => name_groups.length,
      'duplicate_name_actor_count' => name_groups.values.flatten.length,
      'duplicate_name_groups' => name_groups,
      'duplicate_url_group_count' => url_groups.length,
      'duplicate_url_actor_count' => url_groups.values.flatten.length,
      'duplicate_url_groups' => url_groups,
      'collision_groups' => groups
    }
  end

  def duplicate_groups(actors)
    actors.each_with_index.with_object({}) do |(actor, position), index|
      key = yield(actor)
      next if key.nil? || key.empty?

      index[key] ||= []
      index[key] << position
    end.select { |_key, positions| positions.length > 1 }
         .sort.to_h
         .transform_values do |positions|
           positions.map do |position|
             actor = actors.fetch(position)
             {
               'position' => position,
               'source_file' => actor['_source_file'],
               'name' => actor['name'],
               'url' => actor['url']
             }
           end
         end
  end
end
