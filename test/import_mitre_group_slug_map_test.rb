# frozen_string_literal: true

require 'json'
require 'fileutils'
require 'minitest/autorun'
require 'set'
require 'tmpdir'
require_relative '../scripts/import-mitre'
require_relative '../scripts/mitre/entity_writers'

class ImportMitreGroupSlugMapTest < Minitest::Test
  FakeResolver = Struct.new(:intrusion_sets)

  def setup
    @importer = MitreAttackImporter.new([])
  end

  def test_colliding_alias_is_excluded_from_name_match_fallback
    existing = [
      {
        'name' => 'Cerber One',
        'aliases' => %w[Cerber c3rb3r],
        'url' => '/cerber-one/'
      },
      {
        'name' => 'Cerber Two',
        'aliases' => ['Cerber'],
        'url' => '/cerber-two/'
      }
    ]
    alias_index = ImportUtils.build_alias_index(existing)

    # Intrusion set whose primary name is the colliding alias "Cerber".
    intrusion = {
      'id' => 'intrusion-set--cerber-ambiguous',
      'type' => 'intrusion-set',
      'name' => 'Cerber',
      'aliases' => ['Cerber'],
      'external_references' => []
    }
    resolver = FakeResolver.new([intrusion])

    map = @importer.send(:build_group_slug_map, resolver, existing, alias_index, {})
    entry = map['intrusion-set--cerber-ambiguous']

    refute_nil entry
    # Ambiguous alias must not resolve to the first colliding actor via name_match.
    refute_equal '/cerber-one/', entry['url']
    refute_equal '/cerber-two/', entry['url']
    assert_nil entry['url']
    assert_equal 'Cerber', entry['name']
  end

  def test_unique_canonical_name_still_resolves
    existing = [
      {
        'name' => 'APT29',
        'aliases' => %w[Cozy Bear APT29],
        'url' => '/apt29/',
        'mitre_id' => 'G0016'
      }
    ]
    alias_index = ImportUtils.build_alias_index(existing)
    intrusion = {
      'id' => 'intrusion-set--apt29',
      'type' => 'intrusion-set',
      'name' => 'APT29',
      'aliases' => ['Cozy Bear'],
      'external_references' => [
        { 'source_name' => 'mitre-attack', 'external_id' => 'G0016', 'url' => 'https://attack.mitre.org/groups/G0016' }
      ]
    }
    resolver = FakeResolver.new([intrusion])

    map = @importer.send(:build_group_slug_map, resolver, existing, alias_index, {})
    entry = map['intrusion-set--apt29']

    assert_equal '/apt29/', entry['url']
    assert_equal 'APT29', entry['name']
  end
end

class MitreTechniqueGroupUrlTest < Minitest::Test
  class StubResolver
    def groups_using_technique(_stix_id)
      %w[gid-linked gid-unresolved]
    end

    def parent_technique_stix_id(_stix_id) = nil
    def object_for_stix_id(_sid) = nil
    def tactics_for_technique(_stix_id) = []
    def mitigations_for_technique(_stix_id) = []
    def subtechnique_stix_ids(_stix_id) = []
  end

  def test_write_technique_file_renders_plain_name_without_empty_url
    Dir.mktmpdir do |dir|
      Dir.chdir(dir) do
        FileUtils.mkdir_p('_techniques')
        group_slug_map = {
          'gid-linked' => { 'name' => 'APT29', 'url' => '/apt29/' },
          'gid-unresolved' => { 'name' => 'Unresolved Group' }
        }
        writers = MitreEntityWriters.new(
          StubResolver.new,
          { 'attack-pattern--demo' => ['enterprise'] },
          group_slug_map: group_slug_map
        )

        obj = {
          'id' => 'attack-pattern--demo',
          'name' => 'Demo Technique',
          'description' => 'A technique.',
          'external_references' => [
            { 'source_name' => 'mitre-attack', 'external_id' => 'T9999', 'url' => 'https://attack.mitre.org/techniques/T9999' }
          ]
        }
        writers.send(:write_technique_file, obj, 'T9999')

        body = File.read('_techniques/t9999.md')
        assert_includes body, '- [APT29](/apt29/)'
        assert_includes body, '- Unresolved Group'
        refute_match(/\[Unresolved Group\]\(\)/, body)
        refute_match(/\[Unresolved Group\]\(\s*\)/, body)

        data = JSON.parse(File.read('_techniques/t9999.data.json'))
        unresolved = data['groups'].find { |g| g['name'] == 'Unresolved Group' }
        refute unresolved.key?('url')
      end
    end
  end
end
