# frozen_string_literal: true

require 'minitest/autorun'
require 'yaml'
require_relative '../scripts/import-misp-galaxy'
require_relative '../scripts/lib/actor_duplicate_audit'
require_relative '../scripts/lib/alias_resolver'

class ActorDuplicateAuditTest < Minitest::Test
  FIXTURE = File.expand_path('fixtures/actor_dedup/actors.yml', __dir__)

  def setup
    @actors = YAML.safe_load(File.read(FIXTURE))
  end

  def test_qilin_records_are_distinct_without_shared_identity_key
    report = ActorDuplicateAudit.report(@actors)

    assert_equal 7, report['actor_count']
    assert_empty report['collision_groups'].select { |group| group['key'].start_with?('qilin') }
  end

  def test_leet_alias_collisions_are_reported_as_ambiguous_not_merged
    report = ActorDuplicateAudit.report(@actors)
    keys = report['collision_groups'].map { |group| group['key'] }

    assert_includes keys, 'cerber'
    assert_includes keys, 'cryptolocker'
    match = AliasResolver.find_match('c3rb3r', [], AliasResolver.build_alias_index(@actors, synonym_path: nil))
    assert_equal :ambiguous, match[:confidence]
    assert_equal [3, 4], match[:positions]
  end

  def test_exact_duplicate_metrics_are_separate_from_alias_collisions
    report = ActorDuplicateAudit.report(@actors)

    assert_equal %w[cerber cryptolocker], report['duplicate_name_groups'].keys
    assert_equal 4, report['duplicate_name_groups'].values.flatten.length
    assert_empty report['duplicate_url_groups']
    refute_empty report['collision_groups']
  end

  def test_misp_symbols_without_url_safe_characters_are_quarantined
    importer = MispGalaxyImporter.new([])
    record = { 'value' => '$$$', 'description' => 'Ransomware', 'uuid' => 'fixture-uuid', 'meta' => {} }

    assert_nil importer.send(:convert_misp_actor, record)
    assert_equal [{ name: '$$$', reason: 'empty_url_slug' }], importer.instance_variable_get(:@skipped_records)
  end

end
