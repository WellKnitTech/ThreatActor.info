# frozen_string_literal: true

require 'minitest/autorun'
require_relative '../scripts/import-dragos-threat-groups'
require_relative '../scripts/import-unit42-threat-actor-groups'

class ImportDragosUnit42DataPathTest < Minitest::Test
  def test_dragos_apply_skips_nil_data_path_without_typeerror
    importer = DragosThreatGroupsImporter.allocate
    warnings = []
    importer.define_singleton_method(:warn) { |message| warnings << message }

    importer.send(:apply_updates, [{ actor_name: 'Demo', data_path: nil, aliases: ['X'],
                                     source_name: 'Demo', source_urls: [] }],
                  { 'retrieved_at' => '2026-10-27T00:00:00Z' })
    assert_match(/missing actor data path/, warnings.join("\n"))
  end

  def test_unit42_apply_skips_nil_data_path_without_typeerror
    importer = Unit42ThreatActorGroupsImporter.allocate
    warnings = []
    importer.define_singleton_method(:warn) { |message| warnings << message }

    importer.send(:apply_updates, [{ actor_name: 'Demo', data_path: nil, aliases: ['X'],
                                     source_name: 'Demo' }],
                  { 'retrieved_at' => '2026-10-27T00:00:00Z' })
    assert_match(/missing actor data path/, warnings.join("\n"))
  end
end
