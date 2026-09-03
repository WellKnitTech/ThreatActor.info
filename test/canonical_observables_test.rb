# frozen_string_literal: true

require 'minitest/autorun'
require 'json'
require 'json_schemer'
require 'yaml'
require_relative '../scripts/canonical_observables'

class CanonicalObservablesTest < Minitest::Test
  ROOT = File.expand_path('fixtures/observables', __dir__)

  def setup
    @valid = YAML.safe_load(File.read(File.join(ROOT, 'valid-observables.yml'))).fetch('observations')
    @invalid = YAML.safe_load(File.read(File.join(ROOT, 'invalid-observables.yml'))).fetch('cases')
  end

  def test_valid_fixture_canonicalizes_and_deduplicates
    records = CanonicalObservables.canonicalize_all(@valid.reject { |row| row['status'] == 'false_positive' })
    assert_equal @valid.length - 1, records.length
    assert_equal 'c2.example.com', records.find { |r| r['type'] == 'domain' }['value']
    assert_equal 2, records.find { |r| r['type'] == 'domain' }['sources'].length
    assert_equal 'CVE-2024-12345', records.find { |r| r['type'] == 'cve' }['value']
    assert records.all? { |r| r['id'].start_with?('obs_v1_') }
    assert_equal records.map { |r| r['id'] }, CanonicalObservables.canonicalize_all(@valid.reject { |row| row['status'] == 'false_positive' }).map { |r| r['id'] }
    schema = JSONSchemer.schema(JSON.parse(File.read(File.expand_path('../schemas/observable.schema.json', __dir__))))
    assert records.all? { |record| schema.valid?(record) }
    assert_equal 'quarantined', records.find { |r| r['value'] == 'conflict.example' }['status']
    refute CanonicalObservables.public?(records.find { |r| r['value'] == 'stale.example' })
  end

  def test_invalid_fixture_fails_closed_with_expected_reasons
    @invalid.each do |row|
      error = assert_raises(ArgumentError) { CanonicalObservables.canonicalize(row) }
      assert_equal row['reason'], error.message, row['name']
    end
  end

  def test_false_positive_is_not_public
    record = CanonicalObservables.canonicalize(@valid.find { |row| row['status'] == 'false_positive' })
    refute CanonicalObservables.public?(record)
  end

  def test_legacy_lists_remain_readable_by_existing_reader
    require_relative '../scripts/ioc_yaml_reader'
    actor = YAML.safe_load(File.read(File.join(ROOT, 'legacy-actor.yml')))
    rows = IocYamlReader.indicator_rows_from_actor(actor)
    assert_equal 1, rows.count { |row| row[:inferred_type] == 'domain' }
    assert_equal 1, rows.count { |row| row[:inferred_type] == 'md5' }
  end

  def test_duplicate_merge_rechecks_conflicting_attribution
    rows = @valid.select { |row| row['value'] == 'conflict.example' }
    rows[1] = Marshal.load(Marshal.dump(rows[0]))
    rows[1]['relationships'] = [{ 'target_kind' => 'actor', 'target_id' => 'apt29', 'role' => 'reported_by' }]
    assert_equal 'quarantined', CanonicalObservables.canonicalize_all(rows).first['status']
  end

  def test_public_requires_every_relationship_to_be_eligible
    record = CanonicalObservables.canonicalize(@valid.first.merge(
      'relationships' => [{ 'target_kind' => 'actor', 'target_id' => 'apt28', 'role' => 'reported_by', 'status' => 'false_positive' }]
    ))
    refute CanonicalObservables.public?(record)
  end

  def test_paths_require_root_and_preserve_posix_and_unc_roots
    base = @valid.find { |row| row['type'] == 'file_path' }
    assert_equal 'C:\\Users\\Public\\payload.exe', CanonicalObservables.canonicalize(base)['value']
    assert_equal '/var/lib/payload.exe', CanonicalObservables.normalize('file_path', '/var/lib/./tmp/../payload.exe')
    assert_equal '\\\\server\\share\\payload.exe', CanonicalObservables.normalize('file_path', '\\\\server\\share\\dir\\..\\payload.exe')
    error = assert_raises(ArgumentError) { CanonicalObservables.normalize('file_path', 'var/lib/payload.exe') }
    assert_equal 'relative_path_forbidden', error.message
  end

  def test_impossible_timestamp_is_rejected
    error = assert_raises(ArgumentError) { CanonicalObservables.canonicalize(@valid.first.merge('first_seen' => '2024-02-30T00:00:00Z')) }
    assert_equal 'invalid_first_seen', error.message
  end

  def test_aggregate_status_is_independent_of_duplicate_input_order
    active = @valid.find { |row| row['value'] == 'c2[.]example.com' }
    deprecated = Marshal.load(Marshal.dump(active)).merge('status' => 'deprecated')
    assert_equal CanonicalObservables.canonicalize_all([active, deprecated]).first['status'],
                 CanonicalObservables.canonicalize_all([deprecated, active]).first['status']
  end

  def test_malformed_relationship_fails_closed
    error = assert_raises(ArgumentError) { CanonicalObservables.canonicalize(@valid.first.merge('relationships' => [{ 'target_kind' => 'unknown' }])) }
    assert_equal 'invalid_relationship', error.message
  end
end
